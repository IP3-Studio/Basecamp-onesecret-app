#pragma once

#include "rep_onesecret_ui_source.h"
#include "logos_ui_plugin_context.h"
#include "crypto.h"
#include "names.h"

#include <QHash>
#include <QHostAddress>
#include <QJsonObject>
#include <QQueue>
#include <QSet>
#include <QString>
#include <QTimer>

#include <functional>
#include <optional>

// Onesecret backend. Runs in the module's ui-host process; the QML view in
// Basecamp talks to it over QtRemoteObjects (src/onesecret_ui.rep).
//
// One secret = one content topic on Logos Messaging. The sender's backend is
// the only holder of the release key K_rel and the ciphertext C. The first
// authenticated claim on the topic gets exactly one release, wrapped to the
// claimant's ephemeral X25519 key; after that the sender destroys K_rel and C.
// "Deletion" is key destruction: the fleet's store nodes keep every message
// for days, so the design makes those bytes inert instead of trying to delete
// them. See README.md for the protocol and the limits.
class OnesecretUiBackend : public OnesecretUiSimpleSource,
                           public LogosUiPluginContext
{
public:
    OnesecretUiBackend();
    ~OnesecretUiBackend() override;

    // .rep SLOTs: sender
    void createSecret(QString name, QString body, int ttlHours, QString passphrase, int maxReads) override;
    void burnSecret(QString id) override;
    void forgetSecret(QString id) override;
    void clearLastLink() override;
    // .rep SLOTs: recipient
    void openLink(QString link, QString passphrase) override;
    void cancelOpen(QString id) override;
    // .rep SLOTs: settings and diagnostics
    void choosePreset(QString preset) override;
    void chooseName(QString name) override;
    void chooseAnonProfile(bool on) override;
    void chooseNameVerify(QString mode) override;
    void copyText(QString text) override;
    void refreshStatus() override;

    void onContextReady() override;

private:
    // ---- persistent records ---------------------------------------------
    // One reader of a secret: the claimant key it was released to, the
    // receipt key, and the envelope kept until the read is acknowledged.
    struct Reader {
        osc::Bytes R;           // claimant's ephemeral public key
        osc::Bytes kAck;        // HKDF(K_wrap, "ack"), verifies this reader's receipt
        QString fp;             // SHA-256(R)[0..4] hex, shown as the device fingerprint
        QJsonObject release;    // the envelope, kept until the ack or expiry
        QString name;           // the name the reader opened as, if any
        osc::Bytes N;           // the reader key the release is also wrapped to, if any
        bool listed = false;    // the name's record listed N when the release was built
        qint64 releasedAt = 0;
        qint64 openedAt = 0;    // acknowledged read
        bool confirmed = false; // a store node holds the release
    };
    // A secret this Basecamp holds (sender side). Mirrors secrets/<id>.sec.
    // States: new (nobody served yet), open (some readers served, more allowed),
    // done (all reads served), expired, burned.
    struct Secret {
        QString id;
        QString topic;
        QString name;
        QString state;
        osc::Bytes kClaim;      // HMAC key for claims and "gone" replies (kept in tombstones)
        osc::Bytes kRel;        // release key, only while reads remain
        osc::Bytes ct;          // C, only while reads remain
        osc::Bytes argonSalt;   // 16 bytes when a passphrase is required, else empty
        osc::Bytes from;        // this secret's own sender id on the wire (16 bytes)
        int maxReads = 1;
        int linkVersion = 1;    // decides what the claim HMAC covers (crypto.h)
        QList<Reader> readers;  // in release order
        qint64 createdAt = 0;
        qint64 expiresAt = 0;
        qint64 tombUntil = 0;   // tombstone retention
        bool subscribed = false;
    };
    // A link this Basecamp is trying to open (recipient side). claims/<id>.clm.
    struct Claim {
        QString id;
        QString topic;
        QString state;          // claiming | release-held | opened | gone | expired | burned | stale
        osc::Bytes kLink;
        osc::Bytes commit;      // 8 bytes from the link
        osc::Bytes kClaim;
        osc::Bytes r;           // ephemeral private
        osc::Bytes R;           // ephemeral public
        osc::Bytes n;           // 16-byte claim nonce
        osc::Bytes from;
        QJsonObject release;    // a release that arrived but needs a passphrase
        QString asName;         // the name this claim is made as ("" for none)
        bool asAnon = false;    // made with the anonymous profile (reader key, no name)
        int linkVersion = 1;    // from the link
        qint64 createdAt = 0;
        qint64 lastBeaconAt = 0;
        int beacons = 0;
        bool subscribed = false;
    };

    // ---- storage ----------------------------------------------------------
    QString m_baseDir;      // <...>/module_data/onesecret_ui
    osc::Bytes m_kRest;     // 32-byte at-rest key, rest.key (0600)
    bool initStorage();
    bool loadRestKey();
    QString secretPath(const QString& id) const;
    QString claimPath(const QString& id) const;
    QString openedPath(const QString& id) const;
    bool writeEncrypted(const QString& path, const QString& aad, const QJsonObject& obj);
    std::optional<QJsonObject> readEncrypted(const QString& path, const QString& aad);
    void secureUnlink(const QString& path);
    void loadAll();
    bool saveSecret(const Secret& s);
    bool saveClaim(const Claim& c);
    QJsonObject secretToJson(const Secret& s) const;
    std::optional<Secret> secretFromJson(const QJsonObject& o) const;
    QJsonObject claimToJson(const Claim& c) const;
    std::optional<Claim> claimFromJson(const QJsonObject& o) const;

    // ---- sender logic -----------------------------------------------------
    QHash<QString, Secret> m_secrets;      // by id (live + tombstones)
    void handleClaim(Secret& s, const QJsonObject& msg);
    bool buildRelease(Secret& s, const osc::Bytes& R, const osc::Bytes& N = {}, const QString& name = {},
                      bool listed = false);
    void releaseTo(const QString& id, const osc::Bytes& R, const osc::Bytes& n, const osc::Bytes& N,
                   const QString& name, bool listed);
    void publishRelease(const Secret& s, const Reader& r);
    Reader* findReader(Secret& s, const osc::Bytes& R);
    int servedCount(const Secret& s) const { return s.readers.size(); }
    bool readsRemain(const Secret& s) const { return s.readers.size() < s.maxReads; }
    void settle(Secret& s);
    void publishGone(const Secret& s, const QString& reason, const osc::Bytes& R, const osc::Bytes& n);
    void handleAck(Secret& s, const QJsonObject& msg);
    void finishSecret(Secret& s, const QString& state, qint64 at);  // wipe + tombstone
    void expireSweep();
    void rebuildSentList();

    // ---- recipient logic --------------------------------------------------
    QHash<QString, Claim> m_claims;        // by id
    QString m_openPassphrase;              // for the id in openId(), memory only
    void startClaim(Claim& c);
    void publishClaimBeacon(Claim& c);
    void handleRelease(Claim& c, const QJsonObject& msg);
    bool tryOpen(Claim& c, const QJsonObject& release, const QString& passphrase);
    void handleGone(Claim& c, const QJsonObject& msg);
    void publishAck(const Claim& c, const osc::Bytes& kAck);
    void finishClaim(Claim& c, const QString& state, const QString& info);
    void beaconSweep();
    void rebuildPendingList();
    void showOpen(const QString& id, const QString& state, const QString& info);

    // ---- names and profiles (docs/names.md) --------------------------------
    // The long-term reader key, created on first use and kept in reader.key
    // sealed under the rest key. The private half never leaves this Basecamp.
    osc::Bytes m_readerPriv;
    osc::Bytes m_readerPub;
    bool ensureReaderKey();
    void loadNameSettings();
    void updateNameRecord();
    static osc::Bytes nmOf(const QJsonObject& claim);
    // Sender side: a claim with a domain name waits for one bounded DNS lookup
    // when verification is on. At most kNameLookupsInFlight at once, a capped
    // queue, answers cached per name.
    struct NameLookup {
        QString id;
        osc::Bytes R, n, N;
        QString name;
        qint64 startedMs = 0;   // 0 while queued
    };
    struct CachedKeys {
        QList<osc::Bytes> keys;
        qint64 at = 0;
    };
    QHash<QString, NameLookup> m_nameLookups;   // by id + ":" + R
    QStringList m_nameQueue;
    int m_nameLookupsInFlight = 0;
    QHash<QString, CachedKeys> m_dnsCache;      // by name
    QHostAddress m_dnsServer;                   // test hook (ONESECRET_DNS_SERVER); default system resolver
    quint16 m_dnsPort = 53;
    void lookUpName(const QString& id, const osc::Bytes& R, const osc::Bytes& n, const osc::names::Tag& tag);
    void pumpNameLookups();
    void finishNameLookup(const QString& key, qint64 started, const QList<osc::Bytes>& keys);

    // ---- delivery glue ----------------------------------------------------
    bool m_eventsArmed = false;
    bool m_deliveryReady = false;
    bool m_connected = false;      // node reports Connected or PartiallyConnected
    bool m_nodeAdopted = false;
    bool m_bootstrapping = false;
    QList<std::function<void(bool)>> m_readyWaiters;
    QHash<QString, QString> m_topicToSecret;
    QHash<QString, QString> m_topicToClaim;
    QHash<QString, QString> m_requestKinds;   // requestId -> "release:<id>" etc.
    QSet<QString> m_seenHashes;
    QQueue<QString> m_seenOrder;
    QSet<QString> m_ownFroms;
    void ensureDelivery(std::function<void(bool)> done);
    void subscribeTopic(const QString& topic, std::function<void(bool)> done);
    void unsubscribeTopic(const QString& topic);
    void publish(const QString& topic, const osc::Bytes& from, QJsonObject obj, const QString& kind);
    void onWireMessage(const QString& hash, const QString& topic, const QByteArray& payload,
                       const QString& source);
    void refreshConnection();
    void setDelivery(const QString& state, const QString& info);
    QString nodeConfig() const;

    // ---- misc -------------------------------------------------------------
    QTimer m_sweepTimer;
    static QString nowIso(qint64 ms);
    static qint64 nowMs();
    static QString b64(const osc::Bytes& b);
    static osc::Bytes unb64(const QString& s);
    static QString fingerprint(const osc::Bytes& R);
};
