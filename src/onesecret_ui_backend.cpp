#include "onesecret_ui_backend.h"

// Generated umbrella: LogosModules (behind modules()) from metadata.json's
// dependencies, here delivery_module.
#include "logos_sdk.h"

#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QDnsLookup>
#include <QUrl>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcessEnvironment>
#include <QSettings>
#include <QStandardPaths>

#ifndef Q_OS_WIN
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <algorithm>

namespace {
const QString kSettingsOrg = QStringLiteral("Logos");
const QString kSettingsApp = QStringLiteral("onesecret_ui");
const QString kPresetKey = QStringLiteral("preset");
const QString kMyNameKey = QStringLiteral("myName");
const QString kAnonProfileKey = QStringLiteral("anonProfile");
const QString kNameVerifyKey = QStringLiteral("nameVerify");
const QString kDefaultPreset = QStringLiteral("logos.dev");
const QByteArray kRestMagic = QByteArrayLiteral("OS1R");

constexpr int kMaxBodyBytes = 64 * 1024;
constexpr int kMaxReaders = 50;
constexpr int kDefaultTtlHours = 24;
constexpr int kMaxTtlHours = 14 * 24;            // the secret lives on the sender's disk, not on the network
constexpr qint64 kHourMs = 3600LL * 1000;
constexpr qint64 kDayMs = 24 * kHourMs;
constexpr qint64 kTombstoneMs = 30 * kDayMs;
// A recipient's request is repeated while unanswered: every 10 minutes on the
// first day, hourly after that, for as long as the longest possible TTL. The
// fleet keeps each repeat for about three days, so a sender who was away
// longer than that still finds a recent one on return.
constexpr qint64 kBeaconIntervalMs = 10 * 60 * 1000;
constexpr qint64 kBeaconSlowIntervalMs = 60 * 60 * 1000;
constexpr qint64 kClaimMaxAgeMs = 14 * kDayMs;
constexpr int kSeenCap = 4000;
constexpr int kSubscribeRetries = 6;
constexpr int kSubscribeRetryMs = 3000;
// Reader-name verification (docs/names.md): one bounded DNS lookup per new
// reader when the sender has switched it on. A secret is never held back by
// it: timeouts, errors and overflow all serve the claim unverified.
constexpr int kNameLookupsInFlight = 3;
constexpr int kNameLookupTimeoutMs = 5000;
constexpr int kNameQueueCap = 32;
constexpr qint64 kDnsCacheMs = 10 * 60 * 1000;

const char* kInfoDek = "onesecret/v1/dek";
const char* kInfoRelease = "onesecret/v1/release";
const char* kInfoAck = "onesecret/v1/ack";

QString presetOrDefault(const QString& p)
{
    return (p == QLatin1String("logos.test") || p == QLatin1String("logos.dev")) ? p : kDefaultPreset;
}

osc::Bytes bytesOf(const QString& s)
{
    const QByteArray u = s.toUtf8();
    return osc::Bytes(u.begin(), u.end());
}

osc::Bytes bytesOf(const QByteArray& u) { return osc::Bytes(u.begin(), u.end()); }

QByteArray qbytes(const osc::Bytes& b)
{
    return QByteArray(reinterpret_cast<const char*>(b.data()), static_cast<int>(b.size()));
}

bool isLive(const QString& st)
{
    return st == QLatin1String("new") || st == QLatin1String("open");
}
} // namespace

// ---------------------------------------------------------------------------
// Construction and context

OnesecretUiBackend::OnesecretUiBackend()
{
    m_sweepTimer.setInterval(60 * 1000);
    QObject::connect(&m_sweepTimer, &QTimer::timeout, &m_sweepTimer, [this]() {
        expireSweep();
        beaconSweep();
    });
}

OnesecretUiBackend::~OnesecretUiBackend()
{
    for (auto& s : m_secrets) {
        osc::wipe(s.kRel);
        osc::wipe(s.ct);
        for (auto& r : s.readers)
            osc::wipe(r.kAck);
    }
    for (auto& c : m_claims) {
        osc::wipe(c.r);
        osc::wipe(c.kLink);
    }
    osc::wipe(m_readerPriv);
    osc::wipe(m_kRest);
}

void OnesecretUiBackend::onContextReady()
{
    setPreset(presetOrDefault(
        QSettings(kSettingsOrg, kSettingsApp).value(kPresetKey, kDefaultPreset).toString()));
    // The backend runs in ui-host, a QtCore process with no QtGui: copying
    // to the clipboard is the view's job (TextEdit.selectAll() + copy()).
    setClipboardAvailable(false);

    std::string st = osc::selfTest();
    if (st.empty())
        st = osc::names::selfTest();
    if (!st.empty()) {
        setLastError(QStringLiteral("Crypto self-test failed (%1). Refusing to run.")
                         .arg(QString::fromStdString(st)));
        setDelivery(QStringLiteral("error"), lastError());
        return;
    }
    if (!initStorage()) {
        setDelivery(QStringLiteral("error"), lastError());
        return;
    }
    loadNameSettings();
    {
        // Test hook: point DNS lookups at a local responder ("host:port").
        const QString dns = QProcessEnvironment::systemEnvironment().value(QStringLiteral("ONESECRET_DNS_SERVER"));
        if (!dns.isEmpty()) {
            m_dnsServer = QHostAddress(dns.section(QLatin1Char(':'), 0, 0));
            m_dnsPort = static_cast<quint16>(dns.section(QLatin1Char(':'), 1, 1).toUInt());
            if (m_dnsPort == 0) m_dnsPort = 53;
        }
    }
    loadAll();
    rebuildSentList();
    rebuildPendingList();
    m_sweepTimer.start();

    setDelivery(QStringLiteral("starting"), QStringLiteral("Starting the delivery node…"));
    ensureDelivery([this](bool ok) {
        if (!ok)
            return;
        // Re-arm every topic this Basecamp still answers for or waits on. With
        // store catch-up (delivery_module 0.3+) a resubscribe reuses the
        // persisted backfill record, so claims and releases that arrived while
        // we were down are replayed with source "history".
        for (auto it = m_secrets.begin(); it != m_secrets.end(); ++it) {
            const QString id = it.key();
            subscribeTopic(it->topic, [this, id](bool sok) {
                auto s = m_secrets.find(id);
                if (s == m_secrets.end() || !sok)
                    return;
                s->subscribed = true;
                // A release that was never confirmed by a store node may have
                // been lost on the way out; send it again, same key, same R.
                for (const Reader& r : s->readers)
                    if (!r.confirmed && !r.release.isEmpty())
                        publishRelease(*s, r);
            });
        }
        for (auto it = m_claims.begin(); it != m_claims.end(); ++it) {
            const QString id = it.key();
            subscribeTopic(it->topic, [this, id](bool sok) {
                auto c = m_claims.find(id);
                if (c == m_claims.end() || !sok)
                    return;
                c->subscribed = true;
                if (c->state == QLatin1String("claiming"))
                    publishClaimBeacon(*c);
            });
        }
    });
}

// ---------------------------------------------------------------------------
// Small helpers

qint64 OnesecretUiBackend::nowMs() { return QDateTime::currentMSecsSinceEpoch(); }

QString OnesecretUiBackend::nowIso(qint64 ms)
{
    return QDateTime::fromMSecsSinceEpoch(ms).toLocalTime().toString(QStringLiteral("d MMM HH:mm"));
}

QString OnesecretUiBackend::b64(const osc::Bytes& b) { return QString::fromStdString(osc::base64url(b)); }

osc::Bytes OnesecretUiBackend::unb64(const QString& s)
{
    const auto d = osc::fromBase64url(s.toStdString());
    return d ? *d : osc::Bytes();
}

QString OnesecretUiBackend::fingerprint(const osc::Bytes& R)
{
    const osc::Bytes h = osc::sha256(R);
    return QString::fromStdString(osc::hex(osc::Bytes(h.begin(), h.begin() + 4)));
}

// ---------------------------------------------------------------------------
// Storage

bool OnesecretUiBackend::initStorage()
{
    const QString env = QProcessEnvironment::systemEnvironment().value(QStringLiteral("LOGOS_USER_DIR"));
    QString base;
    if (!env.isEmpty())
        base = env;
    else
        base = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
               + QStringLiteral("/Logos/LogosBasecamp");
    m_baseDir = base + QStringLiteral("/module_data/onesecret_ui");
    QDir d(m_baseDir);
    for (const QString& sub : {QStringLiteral("secrets"), QStringLiteral("claims"), QStringLiteral("opened")}) {
        if (!d.mkpath(sub)) {
            setLastError(QStringLiteral("Cannot create %1/%2").arg(m_baseDir, sub));
            return false;
        }
    }
#ifndef Q_OS_WIN
    ::chmod(m_baseDir.toLocal8Bit().constData(), 0700);
#endif
    setDataDir(m_baseDir);
    return loadRestKey();
}

bool OnesecretUiBackend::loadRestKey()
{
    const QString path = m_baseDir + QStringLiteral("/rest.key");
    QFile f(path);
    if (f.exists()) {
        if (!f.open(QIODevice::ReadOnly)) {
            setLastError(QStringLiteral("Cannot read %1").arg(path));
            return false;
        }
        const QByteArray k = f.readAll();
        if (k.size() != 32) {
            setLastError(QStringLiteral("%1 is corrupt (expected 32 bytes)").arg(path));
            return false;
        }
        m_kRest = bytesOf(k);
        return true;
    }
    m_kRest = osc::randomBytes(32);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        setLastError(QStringLiteral("Cannot create %1").arg(path));
        return false;
    }
    f.write(qbytes(m_kRest));
    f.flush();
#ifndef Q_OS_WIN
    ::fsync(f.handle());
#endif
    f.close();
#ifndef Q_OS_WIN
    ::chmod(path.toLocal8Bit().constData(), 0600);
#endif
    return true;
}

QString OnesecretUiBackend::secretPath(const QString& id) const
{
    return m_baseDir + QStringLiteral("/secrets/") + id + QStringLiteral(".sec");
}
QString OnesecretUiBackend::claimPath(const QString& id) const
{
    return m_baseDir + QStringLiteral("/claims/") + id + QStringLiteral(".clm");
}
QString OnesecretUiBackend::openedPath(const QString& id) const
{
    return m_baseDir + QStringLiteral("/opened/") + id + QStringLiteral(".json");
}

// Atomic, encrypted write: temp file, flush, fsync, rename over the target.
bool OnesecretUiBackend::writeEncrypted(const QString& path, const QString& aad, const QJsonObject& obj)
{
    osc::Bytes plain = bytesOf(QJsonDocument(obj).toJson(QJsonDocument::Compact));
    const osc::Bytes iv = osc::randomBytes(12);
    osc::Bytes ct;
    try {
        ct = osc::aesGcmSeal(m_kRest, iv, plain, bytesOf(aad));
    } catch (const std::exception& e) {
        osc::wipe(plain);
        setLastError(QStringLiteral("Encrypting %1 failed: %2").arg(path, e.what()));
        return false;
    }
    osc::wipe(plain);
    const QString tmp = path + QStringLiteral(".tmp");
    QFile f(tmp);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        setLastError(QStringLiteral("Cannot write %1").arg(tmp));
        return false;
    }
    f.write(kRestMagic);
    f.write(qbytes(iv));
    f.write(qbytes(ct));
    f.flush();
#ifndef Q_OS_WIN
    ::fsync(f.handle());
#endif
    f.close();
#ifndef Q_OS_WIN
    ::chmod(tmp.toLocal8Bit().constData(), 0600);
#endif
    if (QFile::exists(path) && !QFile::remove(path)) {
        setLastError(QStringLiteral("Cannot replace %1").arg(path));
        return false;
    }
    if (!QFile::rename(tmp, path)) {
        setLastError(QStringLiteral("Cannot rename %1").arg(tmp));
        return false;
    }
    return true;
}

std::optional<QJsonObject> OnesecretUiBackend::readEncrypted(const QString& path, const QString& aad)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return std::nullopt;
    const QByteArray all = f.readAll();
    if (all.size() < 4 + 12 + 16 || !all.startsWith(kRestMagic))
        return std::nullopt;
    const osc::Bytes iv = bytesOf(all.mid(4, 12));
    const osc::Bytes ct = bytesOf(all.mid(16));
    auto plain = osc::aesGcmOpen(m_kRest, iv, ct, bytesOf(aad));
    if (!plain)
        return std::nullopt;
    const QJsonDocument doc = QJsonDocument::fromJson(qbytes(*plain));
    osc::wipe(*plain);
    if (!doc.isObject())
        return std::nullopt;
    return doc.object();
}

// Overwrite with zeros, fsync, unlink. Not physical erasure on SSD/APFS; the
// at-rest encryption under rest.key is the real control.
void OnesecretUiBackend::secureUnlink(const QString& path)
{
    QFile f(path);
    if (!f.exists())
        return;
    const qint64 size = f.size();
    if (f.open(QIODevice::ReadWrite)) {
        QByteArray zeros(static_cast<int>(std::min<qint64>(size, 1 << 20)), '\0');
        qint64 left = size;
        while (left > 0) {
            const qint64 n = f.write(zeros.constData(), std::min<qint64>(left, zeros.size()));
            if (n <= 0)
                break;
            left -= n;
        }
        f.flush();
#ifndef Q_OS_WIN
        ::fsync(f.handle());
#endif
        f.close();
    }
    QFile::remove(path);
}

QJsonObject OnesecretUiBackend::secretToJson(const Secret& s) const
{
    QJsonObject o;
    o[QStringLiteral("v")] = 2;
    o[QStringLiteral("id")] = s.id;
    o[QStringLiteral("topic")] = s.topic;
    o[QStringLiteral("name")] = s.name;
    o[QStringLiteral("state")] = s.state;
    o[QStringLiteral("kClaim")] = b64(s.kClaim);
    if (!s.kRel.empty()) o[QStringLiteral("kRel")] = b64(s.kRel);
    if (!s.ct.empty()) o[QStringLiteral("ct")] = b64(s.ct);
    if (!s.argonSalt.empty()) o[QStringLiteral("argonSalt")] = b64(s.argonSalt);
    o[QStringLiteral("from")] = b64(s.from);
    o[QStringLiteral("maxReads")] = s.maxReads;
    o[QStringLiteral("linkVersion")] = s.linkVersion;
    QJsonArray readers;
    for (const Reader& r : s.readers) {
        QJsonObject ro;
        ro[QStringLiteral("R")] = b64(r.R);
        if (!r.kAck.empty()) ro[QStringLiteral("kAck")] = b64(r.kAck);
        ro[QStringLiteral("fp")] = r.fp;
        if (!r.release.isEmpty()) ro[QStringLiteral("release")] = r.release;
        ro[QStringLiteral("releasedAt")] = static_cast<double>(r.releasedAt);
        ro[QStringLiteral("openedAt")] = static_cast<double>(r.openedAt);
        ro[QStringLiteral("confirmed")] = r.confirmed;
        if (!r.name.isEmpty()) ro[QStringLiteral("name")] = r.name;
        if (!r.N.empty()) ro[QStringLiteral("N")] = b64(r.N);
        if (r.listed) ro[QStringLiteral("listed")] = true;
        readers.append(ro);
    }
    o[QStringLiteral("readers")] = readers;
    o[QStringLiteral("createdAt")] = static_cast<double>(s.createdAt);
    o[QStringLiteral("expiresAt")] = static_cast<double>(s.expiresAt);
    o[QStringLiteral("tombUntil")] = static_cast<double>(s.tombUntil);
    return o;
}

std::optional<OnesecretUiBackend::Secret> OnesecretUiBackend::secretFromJson(const QJsonObject& o) const
{
    Secret s;
    s.id = o.value(QStringLiteral("id")).toString();
    s.topic = o.value(QStringLiteral("topic")).toString();
    s.name = o.value(QStringLiteral("name")).toString();
    s.state = o.value(QStringLiteral("state")).toString();
    s.kClaim = unb64(o.value(QStringLiteral("kClaim")).toString());
    s.kRel = unb64(o.value(QStringLiteral("kRel")).toString());
    s.ct = unb64(o.value(QStringLiteral("ct")).toString());
    s.argonSalt = unb64(o.value(QStringLiteral("argonSalt")).toString());
    s.from = unb64(o.value(QStringLiteral("from")).toString());
    s.maxReads = std::max(1, o.value(QStringLiteral("maxReads")).toInt(1));
    s.linkVersion = o.value(QStringLiteral("linkVersion")).toInt(1);
    s.createdAt = static_cast<qint64>(o.value(QStringLiteral("createdAt")).toDouble());
    s.expiresAt = static_cast<qint64>(o.value(QStringLiteral("expiresAt")).toDouble());
    s.tombUntil = static_cast<qint64>(o.value(QStringLiteral("tombUntil")).toDouble());
    if (o.contains(QStringLiteral("readers"))) {
        for (const QJsonValue& v : o.value(QStringLiteral("readers")).toArray()) {
            const QJsonObject ro = v.toObject();
            Reader r;
            r.R = unb64(ro.value(QStringLiteral("R")).toString());
            r.kAck = unb64(ro.value(QStringLiteral("kAck")).toString());
            r.fp = ro.value(QStringLiteral("fp")).toString();
            r.release = ro.value(QStringLiteral("release")).toObject();
            r.releasedAt = static_cast<qint64>(ro.value(QStringLiteral("releasedAt")).toDouble());
            r.openedAt = static_cast<qint64>(ro.value(QStringLiteral("openedAt")).toDouble());
            r.confirmed = ro.value(QStringLiteral("confirmed")).toBool();
            r.name = ro.value(QStringLiteral("name")).toString();
            r.N = unb64(ro.value(QStringLiteral("N")).toString());
            r.listed = ro.value(QStringLiteral("listed")).toBool();
            if (r.R.size() == 32)
                s.readers.append(r);
        }
    } else {
        // Version 1 record: a single reader kept in top-level fields.
        const osc::Bytes R = unb64(o.value(QStringLiteral("R")).toString());
        if (R.size() == 32) {
            Reader r;
            r.R = R;
            r.kAck = unb64(o.value(QStringLiteral("kAck")).toString());
            r.fp = o.value(QStringLiteral("fp")).toString();
            r.release = o.value(QStringLiteral("release")).toObject();
            r.releasedAt = static_cast<qint64>(o.value(QStringLiteral("releasedAt")).toDouble());
            r.openedAt = static_cast<qint64>(o.value(QStringLiteral("openedAt")).toDouble());
            r.confirmed = o.value(QStringLiteral("releaseConfirmed")).toBool();
            s.readers.append(r);
        }
        if (s.state == QLatin1String("released")) s.state = QStringLiteral("done");
        if (s.state == QLatin1String("opened")) s.state = QStringLiteral("done");
    }
    if (s.id.isEmpty() || s.topic.isEmpty() || s.kClaim.size() != 32 || s.from.size() != 16)
        return std::nullopt;
    if (isLive(s.state) && (s.kRel.size() != 32 || s.ct.empty()))
        return std::nullopt;
    return s;
}

QJsonObject OnesecretUiBackend::claimToJson(const Claim& c) const
{
    QJsonObject o;
    o[QStringLiteral("v")] = 1;
    o[QStringLiteral("id")] = c.id;
    o[QStringLiteral("topic")] = c.topic;
    o[QStringLiteral("state")] = c.state;
    o[QStringLiteral("kLink")] = b64(c.kLink);
    o[QStringLiteral("commit")] = b64(c.commit);
    o[QStringLiteral("kClaim")] = b64(c.kClaim);
    o[QStringLiteral("r")] = b64(c.r);
    o[QStringLiteral("R")] = b64(c.R);
    o[QStringLiteral("n")] = b64(c.n);
    o[QStringLiteral("from")] = b64(c.from);
    if (!c.release.isEmpty()) o[QStringLiteral("release")] = c.release;
    if (!c.asName.isEmpty()) o[QStringLiteral("asName")] = c.asName;
    if (c.asAnon) o[QStringLiteral("asAnon")] = true;
    o[QStringLiteral("linkVersion")] = c.linkVersion;
    o[QStringLiteral("createdAt")] = static_cast<double>(c.createdAt);
    return o;
}

std::optional<OnesecretUiBackend::Claim> OnesecretUiBackend::claimFromJson(const QJsonObject& o) const
{
    Claim c;
    c.id = o.value(QStringLiteral("id")).toString();
    c.topic = o.value(QStringLiteral("topic")).toString();
    c.state = o.value(QStringLiteral("state")).toString();
    c.kLink = unb64(o.value(QStringLiteral("kLink")).toString());
    c.commit = unb64(o.value(QStringLiteral("commit")).toString());
    c.kClaim = unb64(o.value(QStringLiteral("kClaim")).toString());
    c.r = unb64(o.value(QStringLiteral("r")).toString());
    c.R = unb64(o.value(QStringLiteral("R")).toString());
    c.n = unb64(o.value(QStringLiteral("n")).toString());
    c.from = unb64(o.value(QStringLiteral("from")).toString());
    c.release = o.value(QStringLiteral("release")).toObject();
    c.asName = o.value(QStringLiteral("asName")).toString();
    c.asAnon = o.value(QStringLiteral("asAnon")).toBool();
    c.linkVersion = o.value(QStringLiteral("linkVersion")).toInt(1);
    c.createdAt = static_cast<qint64>(o.value(QStringLiteral("createdAt")).toDouble());
    if (c.id.isEmpty() || c.kLink.size() != 32 || c.commit.size() != 8 || c.kClaim.size() != 32
        || c.r.size() != 32 || c.R.size() != 32 || c.n.size() != 16 || c.from.size() != 16)
        return std::nullopt;
    return c;
}

bool OnesecretUiBackend::saveSecret(const Secret& s)
{
    return writeEncrypted(secretPath(s.id), QStringLiteral("secret|") + s.id, secretToJson(s));
}

bool OnesecretUiBackend::saveClaim(const Claim& c)
{
    return writeEncrypted(claimPath(c.id), QStringLiteral("claim|") + c.id, claimToJson(c));
}

void OnesecretUiBackend::loadAll()
{
    const qint64 now = nowMs();
    for (const QFileInfo& fi : QDir(m_baseDir + QStringLiteral("/secrets"))
                                   .entryInfoList({QStringLiteral("*.sec")}, QDir::Files)) {
        const QString id = fi.completeBaseName();
        auto obj = readEncrypted(fi.absoluteFilePath(), QStringLiteral("secret|") + id);
        auto s = obj ? secretFromJson(*obj) : std::nullopt;
        if (!s) {
            qWarning() << "onesecret: dropping unreadable record" << fi.fileName();
            secureUnlink(fi.absoluteFilePath());
            continue;
        }
        if (s->tombUntil > 0 && now > s->tombUntil) {
            secureUnlink(fi.absoluteFilePath());
            continue;
        }
        m_topicToSecret.insert(s->topic, s->id);
        m_secrets.insert(s->id, *s);
    }
    for (const QFileInfo& fi : QDir(m_baseDir + QStringLiteral("/claims"))
                                   .entryInfoList({QStringLiteral("*.clm")}, QDir::Files)) {
        const QString id = fi.completeBaseName();
        auto obj = readEncrypted(fi.absoluteFilePath(), QStringLiteral("claim|") + id);
        auto c = obj ? claimFromJson(*obj) : std::nullopt;
        if (!c) {
            qWarning() << "onesecret: dropping unreadable claim" << fi.fileName();
            secureUnlink(fi.absoluteFilePath());
            continue;
        }
        m_topicToClaim.insert(c->topic, c->id);
        m_claims.insert(c->id, *c);
    }
}

// ---------------------------------------------------------------------------
// Sender

void OnesecretUiBackend::createSecret(QString name, QString body, int ttlHours, QString passphrase, int maxReads)
{
    setLastError(QString());
    if (m_kRest.empty()) {
        setLastError(QStringLiteral("Storage is not ready."));
        return;
    }
    const QByteArray bodyUtf8 = body.toUtf8();
    if (bodyUtf8.trimmed().isEmpty()) {
        setLastError(QStringLiteral("The secret is empty."));
        return;
    }
    if (bodyUtf8.size() > kMaxBodyBytes) {
        setLastError(QStringLiteral("The secret is %1 KB; the limit is 64 KB.").arg(bodyUtf8.size() / 1024));
        return;
    }
    if (ttlHours <= 0)
        ttlHours = kDefaultTtlHours;
    ttlHours = std::min(ttlHours, kMaxTtlHours);
    maxReads = std::clamp(maxReads, 1, kMaxReaders);
    name = name.trimmed().left(80);
    if (name.isEmpty())
        name = QStringLiteral("Secret");

    try {
        osc::Bytes kLink = osc::randomBytes(32);
        osc::Bytes kRel = osc::randomBytes(32);
        const osc::Bytes nonce = osc::randomBytes(12);
        osc::Bytes argonSalt;
        osc::Bytes passKey;
        if (!passphrase.isEmpty()) {
            argonSalt = osc::randomBytes(16);
            auto pk = osc::argon2id(passphrase.toStdString(), argonSalt);
            if (!pk) {
                setLastError(QStringLiteral("This build's libcrypto has no Argon2id; passphrases are unavailable."));
                osc::wipe(kLink);
                osc::wipe(kRel);
                return;
            }
            passKey = *pk;
        }
        const osc::Derived dv = osc::deriveFromLink(kLink);
        const QString id = QString::fromStdString(dv.id);

        QJsonObject pt;
        pt[QStringLiteral("v")] = 1;
        pt[QStringLiteral("name")] = name;
        pt[QStringLiteral("body")] = body;
        osc::Bytes plain = bytesOf(QJsonDocument(pt).toJson(QJsonDocument::Compact));
        osc::Bytes K = osc::dataKey(kLink, kRel, passKey);
        const osc::Bytes aad = bytesOf(QStringLiteral("onesecret/v1|") + id);
        osc::Bytes C = osc::concat(nonce, osc::aesGcmSeal(K, nonce, plain, aad));
        osc::wipe(plain);
        osc::wipe(K);
        osc::wipe(passKey);

        const osc::Bytes commit = osc::commitment(C);
        const QString link = QString::fromStdString(osc::encodeLink(kLink, commit));

        Secret s;
        s.id = id;
        s.topic = QString::fromStdString(dv.topic);
        s.name = name;
        s.state = QStringLiteral("new");
        s.kClaim = dv.kClaim;
        s.kRel = kRel;
        s.ct = C;
        s.argonSalt = argonSalt;
        s.from = osc::randomBytes(16);
        s.maxReads = maxReads;
        s.linkVersion = osc::kLinkVersion;
        s.createdAt = nowMs();
        s.expiresAt = s.createdAt + qint64(ttlHours) * kHourMs;
        if (!saveSecret(s)) {
            osc::wipe(kLink);
            osc::wipe(kRel);
            osc::wipe(C);
            return;   // lastError already set
        }
        osc::wipe(kLink);   // never on disk; it lives in the link only
        m_secrets.insert(id, s);
        m_topicToSecret.insert(s.topic, id);

        setLastLinkId(id);
        setLastLink(link);
        emit linkCreated(id, link);
        rebuildSentList();

        ensureDelivery([this, id](bool ok) {
            auto it = m_secrets.find(id);
            if (!ok || it == m_secrets.end())
                return;
            subscribeTopic(it->topic, [this, id](bool sok) {
                auto s2 = m_secrets.find(id);
                if (s2 != m_secrets.end())
                    s2->subscribed = sok;
            });
        });
    } catch (const std::exception& e) {
        setLastError(QStringLiteral("Could not create the secret: %1").arg(e.what()));
    }
}

void OnesecretUiBackend::handleClaim(Secret& s, const QJsonObject& msg)
{
    const osc::Bytes R = unb64(msg.value(QStringLiteral("R")).toString());
    const osc::Bytes n = unb64(msg.value(QStringLiteral("n")).toString());
    const osc::Bytes mac = unb64(msg.value(QStringLiteral("mac")).toString());
    if (R.size() != 32 || n.size() != 16 || mac.size() != 32)
        return;
    // Version 2 links: the HMAC also covers the name tag (empty when absent),
    // so a reader's name cannot be stripped from a claim in transit.
    const osc::Bytes nm = nmOf(msg);
    osc::Bytes macInput = osc::concat(bytesOf(QStringLiteral("claim")), bytesOf(s.id), R, n);
    if (s.linkVersion >= 2)
        macInput = osc::concat(macInput, nm);
    const osc::Bytes expect = osc::hmacSha256(s.kClaim, macInput);
    if (!osc::constantTimeEqual(expect, mac))
        return;   // not the link holder; a shard observer or a co-tenant module

    // A new reader with a name tag: an anonymous profile is bound straight
    // away; a domain name is looked up first when verification is on.
    if (!nm.empty() && !findReader(s, R) && isLive(s.state) && readsRemain(s) && nowMs() <= s.expiresAt) {
        if (auto tag = osc::names::openTag(s.kClaim, s.id.toStdString(), R, nm)) {
            const auto kind = tag->name.empty() ? std::nullopt : osc::names::normalise(tag->name);
            if (!tag->name.empty() && kind && kind->kind == osc::names::Kind::Domain
                && nameVerify() == QLatin1String("dns")) {
                lookUpName(s.id, R, n, *tag);
                return;
            }
            releaseTo(s.id, R, n, tag->N, QString::fromStdString(tag->name), false);
            return;
        }
    }
    releaseTo(s.id, R, n, osc::Bytes(), QString(), false);
}

// Answer a verified claim: the stored envelope to a reader already served, a
// new release while reads remain, otherwise an authenticated "gone". N and
// name come from the claim's name tag; listed says whether the name's record
// vouched for N.
void OnesecretUiBackend::releaseTo(const QString& id, const osc::Bytes& R, const osc::Bytes& n,
                                   const osc::Bytes& N, const QString& name, bool listed)
{
    auto it = m_secrets.find(id);
    if (it == m_secrets.end())
        return;
    Secret& s = *it;

    // A reader we already served asks again (their copy was dropped in
    // transit): send the identical envelope. Only the holder of r can open it.
    if (Reader* r = findReader(s, R)) {
        if (!r->release.isEmpty())
            publishRelease(s, *r);
        else
            publishGone(s, QStringLiteral("opened"), R, n);
        return;
    }

    const qint64 now = nowMs();
    if (isLive(s.state)) {
        if (now > s.expiresAt) {
            finishSecret(s, QStringLiteral("expired"), now);
            rebuildSentList();
            publishGone(s, QStringLiteral("expired"), R, n);
            return;
        }
        if (readsRemain(s)) {
            if (!buildRelease(s, R, N, name, listed))
                return;   // lastError set; keep the secret, the claimant will retry
            publishRelease(s, s.readers.last());
            rebuildSentList();
            return;
        }
    }
    QString reason = s.state;
    if (reason != QLatin1String("expired") && reason != QLatin1String("burned"))
        reason = QStringLiteral("opened");
    publishGone(s, reason, R, n);
}

bool OnesecretUiBackend::buildRelease(Secret& s, const osc::Bytes& R, const osc::Bytes& Nin,
                                      const QString& nameIn, bool listedIn)
{
    try {
        osc::KeyPair e = osc::x25519Generate();
        auto ss = osc::x25519Derive(e.priv, R);
        if (!ss) {
            osc::wipe(e.priv);
            setLastError(QStringLiteral("Rejected a claim with an invalid key."));
            return false;
        }
        // A reader key in play: also agree with it, so opening needs both r
        // and that key's private half, and the receipt proves the reader holds
        // it. A reader key that is not a valid point is the claimant's own
        // mistake: serve them without the name rather than refuse.
        osc::Bytes N = Nin;
        QString name = nameIn;
        bool listed = listedIn;
        std::optional<osc::Bytes> ssN;
        if (!N.empty()) {
            ssN = osc::x25519Derive(e.priv, N);
            if (!ssN) {
                N.clear();
                name.clear();
                listed = false;
            }
        }
        std::string info = std::string(kInfoRelease) + osc::toString(e.pub) + osc::toString(R);
        if (ssN) {
            info += osc::toString(N);
            ss->insert(ss->end(), ssN->begin(), ssN->end());
            osc::wipe(*ssN);
        }
        osc::Bytes kWrap = osc::hkdfSha256(*ss, bytesOf(s.id), info, 32);
        osc::wipe(*ss);
        osc::wipe(e.priv);
        osc::Bytes kAck = osc::hkdfSha256(kWrap, osc::Bytes(), kInfoAck, 32);

        osc::Bytes inner;
        inner.push_back(s.argonSalt.empty() ? 0 : 1);
        osc::Bytes salt16 = s.argonSalt.empty() ? osc::Bytes(16, 0) : s.argonSalt;
        inner.insert(inner.end(), salt16.begin(), salt16.end());
        inner.insert(inner.end(), s.kRel.begin(), s.kRel.end());
        inner.insert(inner.end(), s.ct.begin(), s.ct.end());

        const osc::Bytes iv = osc::randomBytes(12);
        const osc::Bytes aad = osc::concat(bytesOf(QStringLiteral("release|") + s.id), e.pub, R, N);
        osc::Bytes wrapped = osc::aesGcmSeal(kWrap, iv, inner, aad);
        osc::wipe(inner);
        osc::wipe(kWrap);

        Reader r;
        r.R = R;
        r.fp = fingerprint(R);
        r.kAck = kAck;
        r.name = name;
        r.N = N;
        r.listed = listed;
        r.releasedAt = nowMs();
        r.release[QStringLiteral("v")] = 1;
        r.release[QStringLiteral("t")] = QStringLiteral("release");
        r.release[QStringLiteral("id")] = s.id;
        r.release[QStringLiteral("E")] = b64(e.pub);
        r.release[QStringLiteral("R")] = b64(R);
        r.release[QStringLiteral("iv")] = b64(iv);
        r.release[QStringLiteral("ct")] = b64(wrapped);
        if (!N.empty())
            r.release[QStringLiteral("N")] = b64(N);

        // Write the new reader, the state and (once the last read is served)
        // the destruction of K_rel and C atomically, before anything is
        // published. A crash between the write and the publish is recovered at
        // the next start: the stored envelope is re-sent to the same R.
        Secret t = s;
        t.readers.append(r);
        const bool last = t.readers.size() >= t.maxReads;
        t.state = last ? QStringLiteral("done") : QStringLiteral("open");
        if (last) {
            osc::wipe(t.kRel);
            osc::wipe(t.ct);
            osc::wipe(t.argonSalt);
        }
        if (!saveSecret(t)) {
            osc::wipe(kAck);
            osc::wipe(wrapped);
            for (auto& tr : t.readers) osc::wipe(tr.kAck);
            osc::wipe(t.kRel);
            osc::wipe(t.ct);
            return false;
        }
        if (last) {
            osc::wipe(s.kRel);
            osc::wipe(s.ct);
            osc::wipe(s.argonSalt);
        }
        s = t;
        return true;
    } catch (const std::exception& ex) {
        setLastError(QStringLiteral("Release failed: %1").arg(ex.what()));
        return false;
    }
}

void OnesecretUiBackend::publishRelease(const Secret& s, const Reader& r)
{
    if (r.release.isEmpty())
        return;
    publish(s.topic, s.from, r.release, QStringLiteral("release:") + s.id + QLatin1Char(':') + r.fp);
}

OnesecretUiBackend::Reader* OnesecretUiBackend::findReader(Secret& s, const osc::Bytes& R)
{
    for (Reader& r : s.readers)
        if (osc::constantTimeEqual(r.R, R))
            return &r;
    return nullptr;
}

void OnesecretUiBackend::publishGone(const Secret& s, const QString& reason, const osc::Bytes& R,
                                     const osc::Bytes& n)
{
    const qint64 at = nowMs();
    const osc::Bytes mac = osc::hmacSha256(
        s.kClaim, osc::concat(osc::concat(bytesOf(QStringLiteral("gone")), bytesOf(s.id), bytesOf(reason)),
                              bytesOf(QString::number(at)), R, n));
    QJsonObject o;
    o[QStringLiteral("t")] = QStringLiteral("gone");
    o[QStringLiteral("id")] = s.id;
    o[QStringLiteral("reason")] = reason;
    o[QStringLiteral("at")] = static_cast<double>(at);
    o[QStringLiteral("R")] = b64(R);
    o[QStringLiteral("n")] = b64(n);
    o[QStringLiteral("mac")] = b64(mac);
    publish(s.topic, s.from, o, QStringLiteral("gone:") + s.id);
}

void OnesecretUiBackend::handleAck(Secret& s, const QJsonObject& msg)
{
    const osc::Bytes R = unb64(msg.value(QStringLiteral("R")).toString());
    const osc::Bytes mac = unb64(msg.value(QStringLiteral("mac")).toString());
    Reader* r = findReader(s, R);
    if (!r || r->kAck.size() != 32 || mac.size() != 32)
        return;
    const osc::Bytes expect = osc::hmacSha256(
        r->kAck, osc::concat(bytesOf(QStringLiteral("ack")), bytesOf(s.id), R));
    if (!osc::constantTimeEqual(expect, mac))
        return;
    if (r->openedAt == 0)
        r->openedAt = nowMs();
    osc::wipe(r->kAck);
    r->release = QJsonObject();
    settle(s);
    rebuildSentList();
}

// Destroy everything that could still open the secret, keep a tombstone so
// later claims get an authenticated "gone".
void OnesecretUiBackend::finishSecret(Secret& s, const QString& state, qint64 at)
{
    // Expiry keeps each served reader's receipt key: that reader may still
    // recover the archived release and acknowledge, which should show as read.
    const bool keepAcks = state == QLatin1String("expired");
    osc::wipe(s.kRel);
    osc::wipe(s.ct);
    osc::wipe(s.argonSalt);
    for (Reader& r : s.readers) {
        r.release = QJsonObject();
        if (!keepAcks)
            osc::wipe(r.kAck);
    }
    s.state = state;
    s.tombUntil = at + kTombstoneMs;
    secureUnlink(secretPath(s.id));
    saveSecret(s);
}

// After a receipt: a secret whose reads are all served and all acknowledged
// becomes a tombstone; otherwise the record is simply saved.
void OnesecretUiBackend::settle(Secret& s)
{
    bool allAcked = s.readers.size() >= s.maxReads;
    for (const Reader& r : s.readers)
        allAcked = allAcked && r.openedAt != 0;
    if (s.state == QLatin1String("done") && allAcked && s.tombUntil == 0) {
        s.tombUntil = nowMs() + kTombstoneMs;
        secureUnlink(secretPath(s.id));
    }
    saveSecret(s);
}

void OnesecretUiBackend::expireSweep()
{
    const qint64 now = nowMs();
    bool changed = false;
    QStringList gone;
    for (auto it = m_secrets.begin(); it != m_secrets.end(); ++it) {
        Secret& s = it.value();
        if (isLive(s.state) && now > s.expiresAt) {
            finishSecret(s, QStringLiteral("expired"), now);
            changed = true;
        } else if (s.state == QLatin1String("done") && now > s.expiresAt && s.tombUntil == 0) {
            // All reads served; readers who never acknowledged get no more
            // resends after the expiry.
            finishSecret(s, QStringLiteral("done"), now);
            changed = true;
        } else if (s.tombUntil > 0 && now > s.tombUntil) {
            gone << s.id;
        }
    }
    for (const QString& id : gone) {
        const Secret s = m_secrets.take(id);
        m_topicToSecret.remove(s.topic);
        unsubscribeTopic(s.topic);
        secureUnlink(secretPath(id));
        changed = true;
    }
    if (changed)
        rebuildSentList();
}

void OnesecretUiBackend::rebuildSentList()
{
    QList<Secret> all = m_secrets.values();
    std::sort(all.begin(), all.end(), [](const Secret& a, const Secret& b) { return a.createdAt > b.createdAt; });
    QJsonArray arr;
    for (const Secret& s : all) {
        int acked = 0;
        QJsonArray readers;
        for (const Reader& r : s.readers) {
            if (r.openedAt) ++acked;
            QJsonObject ro;
            ro[QStringLiteral("fp")] = r.fp;
            ro[QStringLiteral("releasedAt")] = nowIso(r.releasedAt);
            ro[QStringLiteral("openedAt")] = r.openedAt ? nowIso(r.openedAt) : QString();
            ro[QStringLiteral("confirmed")] = r.confirmed;
            // Name and profile. "verified": the name's record listed the key
            // and the holder acknowledged. "bound": released to the key,
            // receipt pending. "claimed": what the reader said, unverified.
            ro[QStringLiteral("name")] = r.name;
            ro[QStringLiteral("anon")] = (r.name.isEmpty() && !r.N.empty()) ? fingerprint(r.N) : QString();
            QString nameState;
            if (!r.N.empty() && r.openedAt == 0)
                nameState = QStringLiteral("bound");
            else if (!r.name.isEmpty() && r.listed && r.openedAt != 0)
                nameState = QStringLiteral("verified");
            else if (!r.name.isEmpty())
                nameState = QStringLiteral("claimed");
            else if (!r.N.empty())
                nameState = QStringLiteral("verified");   // anonymous profile acknowledged
            ro[QStringLiteral("nameState")] = nameState;
            readers.append(ro);
        }
        const int served = s.readers.size();
        QString label;
        if (s.state == QLatin1String("new"))
            label = s.maxReads > 1 ? QStringLiteral("Pending, 0 of %1 read").arg(s.maxReads) : QStringLiteral("Pending");
        else if (s.state == QLatin1String("open"))
            label = QStringLiteral("%1 of %2 read").arg(served).arg(s.maxReads);
        else if (s.state == QLatin1String("done"))
            label = acked == served
                ? (s.maxReads > 1 ? QStringLiteral("Read by all %1").arg(s.maxReads) : QStringLiteral("Opened"))
                : QStringLiteral("All %1 released, %2 confirmed").arg(s.maxReads).arg(acked);
        else if (s.state == QLatin1String("expired"))
            label = served ? QStringLiteral("Expired, %1 of %2 read").arg(served).arg(s.maxReads) : QStringLiteral("Expired");
        else if (s.state == QLatin1String("burned"))
            label = served ? QStringLiteral("Burned, %1 of %2 read").arg(served).arg(s.maxReads) : QStringLiteral("Burned");
        else
            label = s.state;
        QJsonObject o;
        o[QStringLiteral("id")] = s.id;
        o[QStringLiteral("name")] = s.name;
        o[QStringLiteral("state")] = s.state;
        o[QStringLiteral("label")] = label;
        o[QStringLiteral("maxReads")] = s.maxReads;
        o[QStringLiteral("served")] = served;
        o[QStringLiteral("acked")] = acked;
        o[QStringLiteral("readers")] = readers;
        o[QStringLiteral("createdAt")] = nowIso(s.createdAt);
        o[QStringLiteral("expiresAt")] = nowIso(s.expiresAt);
        o[QStringLiteral("ttlHours")] = static_cast<int>((s.expiresAt - s.createdAt) / kHourMs);
        o[QStringLiteral("live")] = isLive(s.state);
        o[QStringLiteral("burnable")] = isLive(s.state) || (s.state == QLatin1String("done") && acked < served);
        arr.append(o);
    }
    setSentList(QString::fromUtf8(QJsonDocument(arr).toJson(QJsonDocument::Compact)));
}

void OnesecretUiBackend::burnSecret(QString id)
{
    auto it = m_secrets.find(id);
    if (it == m_secrets.end())
        return;
    // Burn while reads remain, or while served readers have not yet
    // acknowledged (their pending envelopes are destroyed too).
    bool unacked = false;
    for (const Reader& r : it->readers) unacked = unacked || r.openedAt == 0;
    if (isLive(it->state) || (it->state == QLatin1String("done") && unacked)) {
        finishSecret(*it, QStringLiteral("burned"), nowMs());
        rebuildSentList();
    }
}

void OnesecretUiBackend::forgetSecret(QString id)
{
    auto it = m_secrets.find(id);
    if (it == m_secrets.end())
        return;
    if (it->tombUntil == 0)
        return;   // still live or awaiting receipts; burn first
    const Secret s = *it;
    m_secrets.erase(it);
    m_topicToSecret.remove(s.topic);
    unsubscribeTopic(s.topic);
    secureUnlink(secretPath(id));
    if (lastLinkId() == id)
        clearLastLink();
    rebuildSentList();
}

void OnesecretUiBackend::clearLastLink()
{
    setLastLink(QString());
    setLastLinkId(QString());
}

// ---------------------------------------------------------------------------
// Recipient

void OnesecretUiBackend::showOpen(const QString& id, const QString& state, const QString& info)
{
    setOpenId(id);
    setOpenState(state);
    setOpenInfo(info);
}

void OnesecretUiBackend::openLink(QString link, QString passphrase)
{
    setLastError(QString());
    const auto parts = osc::decodeLink(link.toStdString());
    if (!parts) {
        showOpen(QString(), QStringLiteral("invalid"),
                 QStringLiteral("That is not a complete Onesecret link. Check for a missing or changed character."));
        return;
    }
    const osc::Derived dv = osc::deriveFromLink(parts->kLink);
    const QString id = QString::fromStdString(dv.id);
    m_openPassphrase = passphrase;

    if (QFile::exists(openedPath(id))) {
        QFile f(openedPath(id));
        QString when;
        if (f.open(QIODevice::ReadOnly))
            when = QJsonDocument::fromJson(f.readAll()).object().value(QStringLiteral("at")).toString();
        showOpen(id, QStringLiteral("already"),
                 QStringLiteral("This secret was already opened on this Basecamp%1. It cannot be shown again.")
                     .arg(when.isEmpty() ? QString() : QStringLiteral(" on ") + when));
        return;
    }
    auto it = m_claims.find(id);
    if (it != m_claims.end()) {
        Claim& c = *it;
        if (!c.release.isEmpty()) {
            tryOpen(c, c.release, passphrase);
            return;
        }
        if (c.state == QLatin1String("claiming")) {
            showOpen(id, c.state, QStringLiteral("Still waiting for the sender's Basecamp. Asking again…"));
            if (c.subscribed)
                publishClaimBeacon(c);
            else
                startClaim(c);
            return;
        }
        if (c.state == QLatin1String("stale")) {
            c.state = QStringLiteral("claiming");
            c.createdAt = nowMs();
            c.beacons = 0;
            saveClaim(c);
            rebuildPendingList();
            if (c.subscribed) {
                showOpen(id, c.state, QStringLiteral("Asking the sender's Basecamp again."));
                publishClaimBeacon(c);
            } else {
                startClaim(c);
            }
            return;
        }
        showOpen(id, c.state, openInfo());
        return;
    }

    Claim c;
    c.id = id;
    c.topic = QString::fromStdString(dv.topic);
    c.state = QStringLiteral("claiming");
    c.kLink = parts->kLink;
    c.commit = parts->commit;
    c.kClaim = dv.kClaim;
    c.linkVersion = parts->version;
    c.asName = myName();
    c.asAnon = c.asName.isEmpty() && anonProfile();
    try {
        const osc::KeyPair kp = osc::x25519Generate();
        c.r = kp.priv;
        c.R = kp.pub;
        c.n = osc::randomBytes(16);
        c.from = osc::randomBytes(16);
    } catch (const std::exception& e) {
        setLastError(QStringLiteral("Key generation failed: %1").arg(e.what()));
        return;
    }
    c.createdAt = nowMs();
    if (!saveClaim(c)) {
        showOpen(id, QStringLiteral("error"), lastError());
        return;
    }
    m_claims.insert(id, c);
    m_topicToClaim.insert(c.topic, id);
    rebuildPendingList();
    startClaim(m_claims[id]);
}

void OnesecretUiBackend::startClaim(Claim& c)
{
    const QString id = c.id;
    showOpen(id, QStringLiteral("claiming"),
             QStringLiteral("Asking the sender's Basecamp for the key. This completes when it is online; you can close this and come back."));
    ensureDelivery([this, id](bool ok) {
        auto it = m_claims.find(id);
        if (it == m_claims.end())
            return;
        if (!ok) {
            showOpen(id, QStringLiteral("claiming"), QStringLiteral("The delivery node is not available yet; will retry."));
            return;
        }
        subscribeTopic(it->topic, [this, id](bool sok) {
            auto c2 = m_claims.find(id);
            if (c2 == m_claims.end())
                return;
            c2->subscribed = sok;
            if (!sok)
                return;
            publishClaimBeacon(*c2);
            // While the sender may well be online right now, ask again twice
            // quickly; after that the 60 s sweep takes over at a 10-minute cadence.
            for (int delay : {15000, 40000}) {
                QTimer::singleShot(delay, [this, id]() {
                    auto c3 = m_claims.find(id);
                    if (c3 != m_claims.end() && c3->state == QLatin1String("claiming") && c3->subscribed)
                        publishClaimBeacon(*c3);
                });
            }
        });
    });
}

void OnesecretUiBackend::publishClaimBeacon(Claim& c)
{
    // A send before the node has peers fails with a transient error. Leave it
    // to the sweep (and to the connection handler) once the node is connected.
    if (!m_deliveryReady || !m_connected)
        return;
    // The name tag: the reader key, and the name if any, readable by link
    // holders only. Senders without names support ignore the field.
    osc::Bytes nm;
    if ((!c.asName.isEmpty() || c.asAnon) && m_readerPub.size() == 32) {
        try {
            nm = osc::names::sealTag(c.kClaim, c.id.toStdString(), c.R,
                                     osc::names::Tag{m_readerPub, c.asName.toStdString()});
        } catch (const std::exception&) {
            nm.clear();   // the claim still works, without the name
        }
    }
    osc::Bytes macInput = osc::concat(bytesOf(QStringLiteral("claim")), bytesOf(c.id), c.R, c.n);
    if (c.linkVersion >= 2)
        macInput = osc::concat(macInput, nm);
    const osc::Bytes mac = osc::hmacSha256(c.kClaim, macInput);
    QJsonObject o;
    o[QStringLiteral("t")] = QStringLiteral("claim");
    o[QStringLiteral("id")] = c.id;
    o[QStringLiteral("R")] = b64(c.R);
    o[QStringLiteral("n")] = b64(c.n);
    o[QStringLiteral("mac")] = b64(mac);
    if (!nm.empty())
        o[QStringLiteral("nm")] = b64(nm);
    publish(c.topic, c.from, o, QStringLiteral("claim:") + c.id);
    c.lastBeaconAt = nowMs();
    ++c.beacons;
}

void OnesecretUiBackend::handleRelease(Claim& c, const QJsonObject& msg)
{
    const osc::Bytes R = unb64(msg.value(QStringLiteral("R")).toString());
    if (!osc::constantTimeEqual(R, c.R))
        return;   // addressed to another claimant's key
    QJsonObject rel = msg;
    rel.remove(QStringLiteral("from"));
    const QString pass = (openId() == c.id) ? m_openPassphrase : QString();
    tryOpen(c, rel, pass);
}

bool OnesecretUiBackend::tryOpen(Claim& c, const QJsonObject& rel, const QString& passphrase)
{
    const QString id = c.id;
    const osc::Bytes E = unb64(rel.value(QStringLiteral("E")).toString());
    const osc::Bytes iv = unb64(rel.value(QStringLiteral("iv")).toString());
    const osc::Bytes wrapped = unb64(rel.value(QStringLiteral("ct")).toString());
    if (E.size() != 32 || iv.size() != 12 || wrapped.size() < 16 + 1 + 16 + 32 + 12 + 16) {
        showOpen(id, QStringLiteral("claiming"), QStringLiteral("Received a malformed release; waiting for a resend."));
        return false;
    }
    // A release for a name or profile is also wrapped to the reader key the
    // claim carried; it has to be this Basecamp's. The sender's stored
    // envelope for this R will never change, so a mismatch is final.
    const osc::Bytes N = unb64(rel.value(QStringLiteral("N")).toString());
    if (rel.contains(QStringLiteral("N")) && (N.size() != 32 || m_readerPub.size() != 32
                                              || !osc::constantTimeEqual(N, m_readerPub))) {
        showOpen(id, QStringLiteral("wrong-key"),
                 QStringLiteral("The sender released this to a reader key this Basecamp does not hold (the key changed after the request). Cancel the request; if reads remain, open the link again."));
        return false;
    }
    auto ss = osc::x25519Derive(c.r, E);
    std::optional<osc::Bytes> ssN;
    if (ss && !N.empty())
        ssN = osc::x25519Derive(m_readerPriv, E);
    if (!ss || (!N.empty() && !ssN)) {
        if (ss) osc::wipe(*ss);
        showOpen(id, QStringLiteral("claiming"), QStringLiteral("Received an invalid release; waiting for a resend."));
        return false;
    }
    std::string info = std::string(kInfoRelease) + osc::toString(E) + osc::toString(c.R);
    if (ssN) {
        info += osc::toString(N);
        ss->insert(ss->end(), ssN->begin(), ssN->end());
        osc::wipe(*ssN);
    }
    osc::Bytes kWrap = osc::hkdfSha256(*ss, bytesOf(id), info, 32);
    osc::wipe(*ss);
    const osc::Bytes aad = osc::concat(bytesOf(QStringLiteral("release|") + id), E, c.R, N);
    auto inner = osc::aesGcmOpen(kWrap, iv, wrapped, aad);
    if (!inner) {
        osc::wipe(kWrap);
        showOpen(id, QStringLiteral("claiming"), QStringLiteral("The release did not verify; waiting for a resend."));
        return false;
    }
    const uint8_t flags = (*inner)[0];
    const osc::Bytes salt(inner->begin() + 1, inner->begin() + 17);
    osc::Bytes kRel(inner->begin() + 17, inner->begin() + 49);
    osc::Bytes C(inner->begin() + 49, inner->end());
    osc::wipe(*inner);

    auto bail = [&](const QString& state, const QString& text) {
        osc::wipe(kWrap);
        osc::wipe(kRel);
        osc::wipe(C);
        showOpen(id, state, text);
        return false;
    };

    if (osc::commitment(C) != c.commit)
        return bail(QStringLiteral("corrupt"),
                    QStringLiteral("The content does not match the link. Someone substituted the secret; do not trust it."));

    const bool needsPass = (flags & 1) != 0;
    if (needsPass && passphrase.isEmpty()) {
        c.release = rel;
        c.state = QStringLiteral("release-held");
        saveClaim(c);
        rebuildPendingList();
        return bail(QStringLiteral("needs-passphrase"),
                    QStringLiteral("The key has arrived. This secret also needs a passphrase: enter it and open the link again."));
    }
    osc::Bytes passKey;
    if (needsPass) {
        auto pk = osc::argon2id(passphrase.toStdString(), salt);
        if (!pk)
            return bail(QStringLiteral("error"), QStringLiteral("This build's libcrypto has no Argon2id."));
        passKey = *pk;
    }
    osc::Bytes K = osc::dataKey(c.kLink, kRel, passKey);
    osc::wipe(passKey);
    osc::wipe(kRel);
    const osc::Bytes nonce(C.begin(), C.begin() + 12);
    const osc::Bytes body(C.begin() + 12, C.end());
    auto plain = osc::aesGcmOpen(K, nonce, body, bytesOf(QStringLiteral("onesecret/v1|") + id));
    osc::wipe(K);
    osc::wipe(C);
    if (!plain) {
        if (needsPass) {
            c.release = rel;
            c.state = QStringLiteral("release-held");
            saveClaim(c);
            rebuildPendingList();
            osc::wipe(kWrap);
            showOpen(id, QStringLiteral("needs-passphrase"), QStringLiteral("Wrong passphrase. Try again."));
            return false;
        }
        osc::wipe(kWrap);
        showOpen(id, QStringLiteral("corrupt"), QStringLiteral("The secret could not be decrypted."));
        return false;
    }
    const QJsonObject pt = QJsonDocument::fromJson(qbytes(*plain)).object();
    osc::wipe(*plain);
    const QString name = pt.value(QStringLiteral("name")).toString();
    const QString text = pt.value(QStringLiteral("body")).toString();

    osc::Bytes kAck = osc::hkdfSha256(kWrap, osc::Bytes(), kInfoAck, 32);
    osc::wipe(kWrap);

    // Mark opened on this device before anything else, so a crash cannot show
    // it twice; then reveal, then tell the sender.
    {
        QJsonObject marker;
        marker[QStringLiteral("id")] = id;
        marker[QStringLiteral("at")] = nowIso(nowMs());
        QFile f(openedPath(id));
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write(QJsonDocument(marker).toJson(QJsonDocument::Compact));
            f.close();
        }
    }
    emit secretRevealed(id, name, text);
    publishAck(c, kAck);
    osc::wipe(kAck);
    m_openPassphrase.clear();
    finishClaim(c, QStringLiteral("opened"),
                QStringLiteral("Opened. The sender's copy is being destroyed; this cannot be shown again."));
    return true;
}

void OnesecretUiBackend::publishAck(const Claim& c, const osc::Bytes& kAck)
{
    const osc::Bytes mac = osc::hmacSha256(
        kAck, osc::concat(bytesOf(QStringLiteral("ack")), bytesOf(c.id), c.R));
    QJsonObject o;
    o[QStringLiteral("t")] = QStringLiteral("ack");
    o[QStringLiteral("id")] = c.id;
    o[QStringLiteral("R")] = b64(c.R);
    o[QStringLiteral("mac")] = b64(mac);
    publish(c.topic, c.from, o, QStringLiteral("ack:") + c.id);
}

void OnesecretUiBackend::handleGone(Claim& c, const QJsonObject& msg)
{
    const QString reason = msg.value(QStringLiteral("reason")).toString();
    const qint64 at = static_cast<qint64>(msg.value(QStringLiteral("at")).toDouble());
    const osc::Bytes R = unb64(msg.value(QStringLiteral("R")).toString());
    const osc::Bytes n = unb64(msg.value(QStringLiteral("n")).toString());
    const osc::Bytes mac = unb64(msg.value(QStringLiteral("mac")).toString());
    if (!osc::constantTimeEqual(R, c.R) || !osc::constantTimeEqual(n, c.n) || mac.size() != 32)
        return;
    const osc::Bytes expect = osc::hmacSha256(
        c.kClaim, osc::concat(osc::concat(bytesOf(QStringLiteral("gone")), bytesOf(c.id), bytesOf(reason)),
                              bytesOf(QString::number(at)), R, n));
    if (!osc::constantTimeEqual(expect, mac))
        return;
    QString text;
    if (reason == QLatin1String("expired"))
        text = QStringLiteral("This secret expired before it was opened.");
    else if (reason == QLatin1String("burned"))
        text = QStringLiteral("The sender burned this secret before it was opened.");
    else
        text = QStringLiteral("This secret has already been read as many times as the sender allowed. The sender's Basecamp will not release it again.");
    // "opened" is the sender's reason; the view state for a refused reader is "gone".
    const QString state = (reason == QLatin1String("expired") || reason == QLatin1String("burned"))
        ? reason : QStringLiteral("gone");
    finishClaim(c, state, text);
}

void OnesecretUiBackend::finishClaim(Claim& c, const QString& state, const QString& info)
{
    const QString id = c.id;
    const QString topic = c.topic;
    osc::wipe(c.r);
    osc::wipe(c.kLink);
    osc::wipe(c.kClaim);
    c.release = QJsonObject();
    unsubscribeTopic(topic);
    secureUnlink(claimPath(id));
    m_topicToClaim.remove(topic);
    m_claims.remove(id);   // c is dangling from here on
    showOpen(id, state, info);
    rebuildPendingList();
}

void OnesecretUiBackend::cancelOpen(QString id)
{
    auto it = m_claims.find(id);
    if (it == m_claims.end()) {
        if (openId() == id)
            showOpen(QString(), QStringLiteral("idle"), QString());
        return;
    }
    finishClaim(*it, QStringLiteral("idle"),
                QStringLiteral("Cancelled. If the sender's Basecamp had already released the key to this request, that secret is now unreadable."));
}

void OnesecretUiBackend::beaconSweep()
{
    const qint64 now = nowMs();
    for (auto it = m_claims.begin(); it != m_claims.end(); ++it) {
        Claim& c = it.value();
        if (c.state != QLatin1String("claiming"))
            continue;
        if (now - c.createdAt > kClaimMaxAgeMs) {
            c.state = QStringLiteral("stale");
            saveClaim(c);
            if (openId() == c.id)
                showOpen(c.id, c.state,
                         QStringLiteral("No answer for two weeks. The sender's Basecamp was never online, or the link is dead. Open the link again to retry."));
            continue;
        }
        const qint64 cadence = (now - c.createdAt > kDayMs) ? kBeaconSlowIntervalMs : kBeaconIntervalMs;
        if (c.subscribed && m_connected && now - c.lastBeaconAt >= cadence)
            publishClaimBeacon(c);
    }
    rebuildPendingList();
}

void OnesecretUiBackend::rebuildPendingList()
{
    QList<Claim> all = m_claims.values();
    std::sort(all.begin(), all.end(), [](const Claim& a, const Claim& b) { return a.createdAt > b.createdAt; });
    QJsonArray arr;
    for (const Claim& c : all) {
        QJsonObject o;
        o[QStringLiteral("id")] = c.id;
        o[QStringLiteral("state")] = c.state;
        o[QStringLiteral("createdAt")] = nowIso(c.createdAt);
        o[QStringLiteral("beacons")] = c.beacons;
        arr.append(o);
    }
    setPendingList(QString::fromUtf8(QJsonDocument(arr).toJson(QJsonDocument::Compact)));
}

// ---------------------------------------------------------------------------
// Settings / diagnostics

void OnesecretUiBackend::choosePreset(QString p)
{
    p = presetOrDefault(p);
    QSettings(kSettingsOrg, kSettingsApp).setValue(kPresetKey, p);
    setPreset(p);
    if (m_deliveryReady)
        setDeliveryInfo(QStringLiteral("Preset %1 applies the next time Basecamp starts the delivery node.").arg(p));
}

// ---------------------------------------------------------------------------
// Names and profiles (docs/names.md)

osc::Bytes OnesecretUiBackend::nmOf(const QJsonObject& claim)
{
    return unb64(claim.value(QStringLiteral("nm")).toString());
}

// Creates the reader key on first use. A reader.key that cannot be read is
// reported and the feature stays off; the app itself keeps running.
bool OnesecretUiBackend::ensureReaderKey()
{
    if (m_readerPub.size() == 32 && m_readerPriv.size() == 32)
        return true;
    if (m_kRest.empty())
        return false;
    const QString path = m_baseDir + QStringLiteral("/reader.key");
    if (QFile::exists(path)) {
        const auto obj = readEncrypted(path, QStringLiteral("reader"));
        osc::Bytes priv = obj ? unb64(obj->value(QStringLiteral("priv")).toString()) : osc::Bytes();
        osc::Bytes pub = obj ? unb64(obj->value(QStringLiteral("pub")).toString()) : osc::Bytes();
        if (priv.size() != 32 || pub.size() != 32) {
            osc::wipe(priv);
            setLastError(QStringLiteral("reader.key cannot be read. Delete it to start a new reader identity."));
            return false;
        }
        m_readerPriv = priv;
        m_readerPub = pub;
        osc::wipe(priv);
    } else {
        osc::KeyPair kp = osc::x25519Generate();
        QJsonObject o;
        o[QStringLiteral("priv")] = b64(kp.priv);
        o[QStringLiteral("pub")] = b64(kp.pub);
        const bool ok = writeEncrypted(path, QStringLiteral("reader"), o);
        if (ok) {
            m_readerPriv = kp.priv;
            m_readerPub = kp.pub;
        }
        osc::wipe(kp.priv);
        if (!ok)
            return false;
    }
    setReaderKey(QString::fromStdString(osc::hex(m_readerPub)));
    return true;
}

void OnesecretUiBackend::loadNameSettings()
{
    QSettings st(kSettingsOrg, kSettingsApp);
    const QString verify = st.value(kNameVerifyKey, QStringLiteral("off")).toString();
    setNameVerify(verify == QLatin1String("dns") ? verify : QStringLiteral("off"));
    QString name = st.value(kMyNameKey).toString();
    bool anon = st.value(kAnonProfileKey, false).toBool();
    if (!name.isEmpty()) {
        const auto n = osc::names::normalise(name.toStdString());
        name = n ? QString::fromStdString(n->value) : QString();
    }
    if ((!name.isEmpty() || anon) && !ensureReaderKey()) {
        // The key is gone: switch the identity off rather than claim as nobody.
        name.clear();
        anon = false;
        st.setValue(kMyNameKey, name);
        st.setValue(kAnonProfileKey, anon);
    }
    setMyName(name);
    setAnonProfile(anon);
    updateNameRecord();
}

void OnesecretUiBackend::updateNameRecord()
{
    const auto n = osc::names::normalise(myName().toStdString());
    if (n && n->kind == osc::names::Kind::Domain && m_readerPub.size() == 32)
        setNameRecord(QString::fromStdString(osc::names::recordFor(n->value, m_readerPub)));
    else
        setNameRecord(QString());
}

// The name this Basecamp opens links as. Empty clears it. Claims already in
// progress keep the identity they started with.
void OnesecretUiBackend::chooseName(QString name)
{
    setLastError(QString());
    QString value;
    const QString typed = name.trimmed();
    if (!typed.isEmpty()) {
        // An internationalised domain is converted to its ASCII form first.
        const QString ascii = typed.contains(QLatin1Char('.')) ? QString::fromLatin1(QUrl::toAce(typed)) : typed;
        const auto n = osc::names::normalise(ascii.toStdString());
        if (!n) {
            setLastError(QStringLiteral("\"%1\" is not a name this app can use: a domain such as alice.example.com, or 1 to 32 of a-z, 0-9 and hyphen.").arg(typed));
            return;
        }
        if (!ensureReaderKey())
            return;   // lastError set
        value = QString::fromStdString(n->value);
    }
    QSettings(kSettingsOrg, kSettingsApp).setValue(kMyNameKey, value);
    setMyName(value);
    updateNameRecord();
}

void OnesecretUiBackend::chooseAnonProfile(bool on)
{
    setLastError(QString());
    if (on && !ensureReaderKey()) {
        setAnonProfile(false);
        return;
    }
    QSettings(kSettingsOrg, kSettingsApp).setValue(kAnonProfileKey, on);
    setAnonProfile(on);
}

void OnesecretUiBackend::chooseNameVerify(QString mode)
{
    const QString m = mode == QLatin1String("dns") ? mode : QStringLiteral("off");
    QSettings(kSettingsOrg, kSettingsApp).setValue(kNameVerifyKey, m);
    setNameVerify(m);
}

void OnesecretUiBackend::lookUpName(const QString& id, const osc::Bytes& R, const osc::Bytes& n,
                                    const osc::names::Tag& tag)
{
    const QString key = id + QLatin1Char(':') + b64(R);
    if (m_nameLookups.contains(key))
        return;   // a repeat beacon while the first is still being looked up
    const QString name = QString::fromStdString(tag.name);
    if (m_nameQueue.size() >= kNameQueueCap) {
        releaseTo(id, R, n, tag.N, name, false);   // overflow: served unverified
        return;
    }
    NameLookup l;
    l.id = id;
    l.R = R;
    l.n = n;
    l.N = tag.N;
    l.name = name;
    m_nameLookups.insert(key, l);
    m_nameQueue.append(key);
    pumpNameLookups();
}

void OnesecretUiBackend::pumpNameLookups()
{
    const qint64 now = nowMs();
    while (m_nameLookupsInFlight < kNameLookupsInFlight && !m_nameQueue.isEmpty()) {
        const QString key = m_nameQueue.takeFirst();
        auto it = m_nameLookups.find(key);
        if (it == m_nameLookups.end())
            continue;
        const QString name = it->name;
        auto cached = m_dnsCache.find(name);
        if (cached != m_dnsCache.end() && now - cached->at < kDnsCacheMs) {
            it->startedMs = now;
            ++m_nameLookupsInFlight;
            const QList<osc::Bytes> keys = cached->keys;
            QTimer::singleShot(0, &m_sweepTimer, [this, key, now, keys]() { finishNameLookup(key, now, keys); });
            continue;
        }
        it->startedMs = now;
        ++m_nameLookupsInFlight;
        auto* dns = new QDnsLookup(QDnsLookup::TXT, QLatin1String(osc::names::kRecordPrefix) + name, &m_sweepTimer);
        if (!m_dnsServer.isNull())
            dns->setNameserver(m_dnsServer, m_dnsPort);
        QObject::connect(dns, &QDnsLookup::finished, dns, [this, dns, key, now, name]() {
            QList<osc::Bytes> keys;
            if (dns->error() == QDnsLookup::NoError) {
                std::vector<std::string> records;
                for (const QDnsTextRecord& rec : dns->textRecords()) {
                    QByteArray joined;
                    for (const QByteArray& v : rec.values())
                        joined += v;
                    records.push_back(joined.toStdString());
                }
                for (const osc::Bytes& k : osc::names::listedKeys(records))
                    keys.append(k);
                m_dnsCache.insert(name, CachedKeys{keys, nowMs()});
            }
            dns->deleteLater();
            finishNameLookup(key, now, keys);
        });
        QTimer::singleShot(kNameLookupTimeoutMs, dns, [dns]() {
            if (!dns->isFinished())
                dns->abort();   // emits finished() with OperationCancelledError
        });
        dns->lookup();
    }
}

void OnesecretUiBackend::finishNameLookup(const QString& key, qint64 started, const QList<osc::Bytes>& keys)
{
    auto it = m_nameLookups.find(key);
    if (it == m_nameLookups.end() || it->startedMs != started)
        return;   // already answered, or a later attempt
    const NameLookup l = *it;
    m_nameLookups.erase(it);
    --m_nameLookupsInFlight;
    QTimer::singleShot(0, &m_sweepTimer, [this]() { pumpNameLookups(); });
    const bool listed = keys.contains(l.N);
    releaseTo(l.id, l.R, l.n, l.N, l.name, listed);
}

void OnesecretUiBackend::copyText(QString)
{
    // No clipboard in ui-host (QtCore only); the QML view copies. Kept in the
    // contract so a future host with QtGui can take over without a .rep change.
}

void OnesecretUiBackend::refreshStatus()
{
    expireSweep();
    beaconSweep();
    if (m_deliveryReady)
        refreshConnection();
    else
        ensureDelivery([](bool) {});
}

// ---------------------------------------------------------------------------
// Delivery glue (delivery_module 0.3.x)

QString OnesecretUiBackend::nodeConfig() const
{
    // Layered "app developer" shape from the delivery_module 0.3 contract. A
    // bare top-level logLevel would route the whole config through the legacy
    // flat parser, which pins the p2p port to 60000 and breaks a second
    // instance on the same machine (delivery_module v0.2.1 notes, #82).
    return QStringLiteral("{\"mode\":\"Core\",\"preset\":\"%1\"}").arg(preset());
}

void OnesecretUiBackend::setDelivery(const QString& state, const QString& info)
{
    setDeliveryState(state);
    setDeliveryInfo(info);
}

void OnesecretUiBackend::ensureDelivery(std::function<void(bool)> done)
{
    if (!m_eventsArmed) {
        m_eventsArmed = true;
        modules().delivery_module.onMessageReceived(
            [this](const QString& hash, const QString& contentTopic, QByteArray payload,
                   const QString& source, qlonglong) {
                onWireMessage(hash, contentTopic, payload, source);
            });
        modules().delivery_module.onMessageSent(
            [this](const QString& requestId, const QString&, qlonglong) {
                const QString kind = m_requestKinds.take(requestId);
                if (lastError().startsWith(QLatin1String("Send failed")))
                    setLastError(QString());
                if (kind.startsWith(QLatin1String("release:"))) {
                    const QString id = kind.section(QLatin1Char(':'), 1, 1);
                    const QString fp = kind.section(QLatin1Char(':'), 2, 2);
                    auto it = m_secrets.find(id);
                    if (it != m_secrets.end()) {
                        for (Reader& r : it->readers)
                            if (r.fp == fp && !r.confirmed)
                                r.confirmed = true;
                        saveSecret(*it);
                        rebuildSentList();
                    }
                }
            });
        modules().delivery_module.onMessageError(
            [this](const QString& requestId, const QString&, const QString& error, qlonglong) {
                const QString kind = m_requestKinds.take(requestId);
                if (kind.startsWith(QLatin1String("claim:")))
                    setDeliveryInfo(QStringLiteral("The request could not be sent yet; it will be retried."));
                else
                    setLastError(QStringLiteral("Send failed (%1): %2").arg(kind.section(QLatin1Char(':'), 0, 0), error));
            });
        modules().delivery_module.onConnectionStateChanged(
            [this](const QString& status, qlonglong) {
                const bool was = m_connected;
                if (status == QLatin1String("Connected")) {
                    m_connected = true;
                    setDelivery(QStringLiteral("online"), QStringLiteral("Connected to %1.").arg(preset()));
                } else if (status == QLatin1String("PartiallyConnected")) {
                    m_connected = true;
                    setDelivery(QStringLiteral("partial"), QStringLiteral("Partially connected to %1.").arg(preset()));
                } else {
                    m_connected = false;
                    setDelivery(QStringLiteral("offline"), QStringLiteral("Not connected. Pending secrets wait for the node."));
                }
                if (m_connected && !was)
                    beaconSweep();   // pending claims ask now rather than at the next minute
            });
    }
    if (m_deliveryReady) {
        done(true);
        return;
    }
    m_readyWaiters.append(std::move(done));
    if (m_bootstrapping)
        return;
    m_bootstrapping = true;

    auto finish = [this](bool ok) {
        m_bootstrapping = false;
        m_deliveryReady = ok;
        const auto waiters = m_readyWaiters;
        m_readyWaiters.clear();
        for (const auto& w : waiters)
            w(ok);
        if (ok)
            refreshConnection();
    };

    // Probe first: another module (the Chat app) may already own the node, in
    // which case createNode would be refused and we simply ride on it,
    // inheriting its preset.
    modules().delivery_module.getAvailableNodeInfoIDsAsync([this, finish](LogosResult probe) {
        if (probe.success) {
            m_nodeAdopted = true;
            setDelivery(QStringLiteral("starting"), QStringLiteral("Using the delivery node another app started."));
            finish(true);
            return;
        }
        modules().delivery_module.createNodeAsync(nodeConfig(), [this, finish](LogosResult cr) {
            if (!cr.success)
                setDelivery(QStringLiteral("starting"), QStringLiteral("createNode: %1").arg(cr.getError()));
            modules().delivery_module.startAsync([this, finish](LogosResult sr) {
                if (!sr.success)
                    setDelivery(QStringLiteral("error"), QStringLiteral("The delivery node did not start: %1").arg(sr.getError()));
                // Subscribe is the call that has to succeed; it retries below.
                finish(true);
            });
        });
    });
}

void OnesecretUiBackend::subscribeTopic(const QString& topic, std::function<void(bool)> done)
{
    auto attempt = std::make_shared<std::function<void(int)>>();
    std::weak_ptr<std::function<void(int)>> weak = attempt;
    *attempt = [this, topic, done, weak](int left) {
        // The pending subscribeAsync callback keeps `attempt` alive; the stored
        // function itself only holds a weak reference, so no cycle.
        auto self = weak.lock();
        if (!self)
            return;
        modules().delivery_module.subscribeAsync(topic, [this, topic, done, self, left](LogosResult r) {
            if (r.success) {
                done(true);
                return;
            }
            if (left > 0) {
                QTimer::singleShot(kSubscribeRetryMs, [self, left]() { (*self)(left - 1); });
                return;
            }
            setDelivery(QStringLiteral("error"), QStringLiteral("Could not subscribe: %1").arg(r.getError()));
            done(false);
        });
    };
    (*attempt)(kSubscribeRetries);
}

void OnesecretUiBackend::unsubscribeTopic(const QString& topic)
{
    if (m_deliveryReady && !m_topicToSecret.contains(topic) && !m_topicToClaim.contains(topic))
        modules().delivery_module.unsubscribeAsync(topic, [](LogosResult) {});
}

void OnesecretUiBackend::publish(const QString& topic, const osc::Bytes& from, QJsonObject obj, const QString& kind)
{
    if (!m_deliveryReady) {
        setLastError(QStringLiteral("Not connected yet; %1 will be sent once the node is up.").arg(kind.section(QLatin1Char(':'), 0, 0)));
        return;
    }
    obj[QStringLiteral("v")] = 1;
    obj[QStringLiteral("from")] = b64(from);
    const QByteArray payload = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    modules().delivery_module.sendAsync(topic, payload, [this, kind](LogosResult r) {
        if (!r.success) {
            if (kind.startsWith(QLatin1String("claim:")))
                setDeliveryInfo(QStringLiteral("The request could not be sent yet; it will be retried."));
            else
                setLastError(QStringLiteral("Send failed (%1): %2").arg(kind.section(QLatin1Char(':'), 0, 0), r.getError()));
            return;
        }
        const QString requestId = r.value.toString();
        if (!requestId.isEmpty())
            m_requestKinds.insert(requestId, kind);
        while (m_requestKinds.size() > 500)
            m_requestKinds.erase(m_requestKinds.begin());
    });
}

void OnesecretUiBackend::onWireMessage(const QString& hash, const QString& topic, const QByteArray& payload,
                                       const QString& /*source*/)
{
    if (!hash.isEmpty()) {
        if (m_seenHashes.contains(hash))
            return;
        m_seenHashes.insert(hash);
        m_seenOrder.enqueue(hash);
        while (m_seenOrder.size() > kSeenCap)
            m_seenHashes.remove(m_seenOrder.dequeue());
    }
    const QJsonObject msg = QJsonDocument::fromJson(payload).object();
    if (msg.isEmpty() || msg.value(QStringLiteral("v")).toInt() != 1)
        return;
    const QString t = msg.value(QStringLiteral("t")).toString();
    const QString id = msg.value(QStringLiteral("id")).toString();

    // Each role only consumes the other role's message types, so our own
    // echoes are ignored by construction.
    if (t == QLatin1String("claim") || t == QLatin1String("ack")) {
        const QString sid = m_topicToSecret.value(topic);
        auto it = m_secrets.find(sid);
        if (it == m_secrets.end() || it->id != id)
            return;
        if (t == QLatin1String("claim"))
            handleClaim(*it, msg);
        else
            handleAck(*it, msg);
        return;
    }
    if (t == QLatin1String("release") || t == QLatin1String("gone")) {
        const QString cid = m_topicToClaim.value(topic);
        auto it = m_claims.find(cid);
        if (it == m_claims.end() || it->id != id)
            return;
        if (t == QLatin1String("release"))
            handleRelease(*it, msg);
        else
            handleGone(*it, msg);
    }
}

void OnesecretUiBackend::refreshConnection()
{
    modules().delivery_module.getConnectionStatusAsync([this](LogosResult r) {
        if (!r.success) {
            setDelivery(QStringLiteral("offline"), QStringLiteral("Node status unavailable: %1").arg(r.getError()));
            return;
        }
        const QString st = r.value.toString();
        const bool was = m_connected;
        if (st == QLatin1String("Connected")) {
            m_connected = true;
            setDelivery(QStringLiteral("online"), QStringLiteral("Connected to %1%2.").arg(preset(), m_nodeAdopted ? QStringLiteral(" (node started by another app)") : QString()));
        } else if (st == QLatin1String("PartiallyConnected")) {
            m_connected = true;
            setDelivery(QStringLiteral("partial"), QStringLiteral("Partially connected to %1.").arg(preset()));
        } else {
            m_connected = false;
            setDelivery(QStringLiteral("offline"), QStringLiteral("Not connected. Pending secrets wait for the node."));
        }
        if (m_connected && !was)
            beaconSweep();
    });
}
