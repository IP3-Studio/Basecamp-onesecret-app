import QtQuick
import QtQuick.Layouts

import Logos.Theme
import Logos.Controls

// Onesecret view. Runs inside Basecamp; the backend runs in the module's
// ui-host process and is reached through the typed replica logos.module().
// Dialogs are in-scene overlays (Popup does not paint reliably inside
// Basecamp's embedded QQuickWidget).
Item {
    id: root
    objectName: "onesecretRoot"
    implicitWidth: 1080
    implicitHeight: 700

    readonly property var backend: (typeof logos !== "undefined" && logos) ? logos.module("onesecret_ui") : null
    property bool ready: false

    // --- backend state (auto-synced PROPs, defensively coerced) ---
    readonly property string sentListJson: ready && backend && backend.sentList ? backend.sentList : "[]"
    readonly property string pendingListJson: ready && backend && backend.pendingList ? backend.pendingList : "[]"
    readonly property string lastLink: ready && backend && backend.lastLink ? backend.lastLink : ""
    readonly property string lastLinkId: ready && backend && backend.lastLinkId ? backend.lastLinkId : ""
    readonly property string openState: ready && backend && backend.openState ? backend.openState : "idle"
    readonly property string openInfo: ready && backend && backend.openInfo ? backend.openInfo : ""
    readonly property string openId: ready && backend && backend.openId ? backend.openId : ""
    readonly property string deliveryState: ready && backend && backend.deliveryState ? backend.deliveryState : "starting"
    readonly property string deliveryInfo: ready && backend && backend.deliveryInfo ? backend.deliveryInfo : ""
    readonly property string preset: ready && backend && backend.preset ? backend.preset : "logos.dev"
    readonly property string dataDir: ready && backend && backend.dataDir ? backend.dataDir : ""
    readonly property string lastError: ready && backend && backend.lastError ? backend.lastError : ""
    readonly property string myName: ready && backend && backend.myName ? backend.myName : ""
    readonly property string readerKey: ready && backend && backend.readerKey ? backend.readerKey : ""
    readonly property bool anonProfile: ready && backend ? backend.anonProfile === true : false
    readonly property string nameVerify: ready && backend && backend.nameVerify ? backend.nameVerify : "off"
    readonly property string nameRecord: ready && backend && backend.nameRecord ? backend.nameRecord : ""
    readonly property bool myNameIsDomain: myName.indexOf(".") !== -1
    readonly property string keyStore: ready && backend && backend.keyStore ? backend.keyStore : ""

    readonly property var sent: { try { return JSON.parse(sentListJson) } catch (e) { return [] } }
    readonly property var pending: { try { return JSON.parse(pendingListJson) } catch (e) { return [] } }

    // --- local UI state ---
    // Expiry: four presets plus a custom amount in hours or days (1 hour to 14 days).
    property int ttlIndex: 1
    readonly property var ttlHours: [1, 24, 48, 72]
    readonly property var ttlLabels: ["1 hour", "24 hours", "48 hours", "72 hours"]
    property bool ttlCustom: false
    property int customAmount: 7
    property string customUnit: "days"
    readonly property int customHours: customUnit === "days" ? customAmount * 24 : customAmount
    readonly property int effectiveTtlHours: ttlCustom ? customHours : ttlHours[ttlIndex]
    readonly property bool ttlValid: effectiveTtlHours >= 1 && effectiveTtlHours <= 14 * 24
    readonly property string ttlPreview: ttlValid
        ? Qt.formatDateTime(new Date(Date.now() + effectiveTtlHours * 3600000), "d MMM yyyy HH:mm")
        : ""
    // Readers: how many different people may read the secret, once each.
    readonly property var readerPresets: [1, 2, 3, 5]
    property int readerIndex: 0
    property bool readersCustom: false
    property int customReaders: 10
    readonly property int effectiveReaders: readersCustom ? customReaders : readerPresets[readerIndex]
    readonly property bool readersValid: effectiveReaders >= 1 && effectiveReaders <= 50
    property bool showReveal: false
    property string revealName: ""
    property string revealBody: ""
    property bool showBurnConfirm: false
    property string burnId: ""
    property string burnName: ""

    function stateColour(st) {
        if (st === "online") return Theme.palette.success
        if (st === "partial" || st === "starting") return Theme.palette.warning
        if (st === "error") return Theme.palette.error
        return Theme.palette.textTertiary
    }
    function stateLabel(st) {
        if (st === "online") return "connected"
        if (st === "partial") return "partly connected"
        if (st === "starting") return "starting"
        if (st === "error") return "error"
        return "offline"
    }
    function ladderColour(st) {
        if (st === "new") return Theme.palette.info
        if (st === "open") return Theme.palette.warning
        if (st === "done") return Theme.palette.success
        if (st === "burned") return Theme.palette.error
        return Theme.palette.textTertiary
    }
    // What a reader's name or profile means on the Sent tab. Only "verified"
    // says the name's record vouched for the key and its holder read it.
    function readerName(r) {
        if (!r) return ""
        if (r.anon) return "  ·  anon profile " + r.anon + (r.nameState === "verified" ? "" : ", receipt pending")
        if (!r.name) return ""
        if (r.nameState === "verified") return "  ·  " + r.name + (r.how === "names" ? ", Logos name verified" : ", DNS-verified")
        if (r.nameState === "bound") return "  ·  says " + r.name + ", receipt pending"
        return "  ·  says " + r.name + " (not verified)"
    }
    function openSeverity(st) {
        if (st === "opened") return LogosNotice.Success
        if (st === "claiming" || st === "idle" || st === "needs-passphrase") return LogosNotice.Info
        if (st === "corrupt" || st === "error" || st === "invalid" || st === "wrong-key") return LogosNotice.Error
        return LogosNotice.Warning
    }
    function openTitle(st) {
        if (st === "claiming") return "Waiting for the sender's Basecamp"
        if (st === "needs-passphrase") return "Passphrase needed"
        if (st === "opened") return "Opened"
        if (st === "already") return "Already opened here"
        if (st === "gone" || st === "opened-elsewhere") return "Already opened"
        if (st === "expired") return "Expired"
        if (st === "burned") return "Burned by the sender"
        if (st === "stale") return "No answer"
        if (st === "invalid") return "Not a valid link"
        if (st === "corrupt") return "Content did not verify"
        if (st === "wrong-key") return "Released to another reader key"
        if (st === "error") return "Error"
        return ""
    }

    Connections {
        target: logos
        function onViewModuleReadyChanged(moduleName, isReady) {
            if (moduleName === "onesecret_ui")
                root.ready = isReady && root.backend !== null
        }
    }
    Component.onCompleted: {
        root.ready = root.backend !== null && logos.isViewModuleReady("onesecret_ui")
    }

    Connections {
        target: root.backend
        enabled: root.backend !== null
        function onSecretRevealed(id, name, body) {
            root.revealName = name
            root.revealBody = body
            root.showReveal = true
        }
        function onLinkCreated(id, link) {
            nameField.text = ""
            bodyArea.text = ""
            passField.text = ""
            tabs.currentIndex = 0
        }
    }

    Rectangle { anchors.fill: parent; color: Theme.palette.background }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spacing.large
        spacing: Theme.spacing.medium

        // ---------------------------------------------------------------- header
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spacing.medium
            LogosText { text: "Onesecret"; font.pixelSize: Theme.typography.panelTitleText; font.weight: Theme.typography.weightBold }
            LogosBadge {
                objectName: "deliveryBadge"
                text: root.stateLabel(root.deliveryState)
                color: root.stateColour(root.deliveryState)
            }
            Item { Layout.fillWidth: true }
            LogosText { text: "Network"; color: Theme.palette.textTertiary; font.pixelSize: Theme.typography.secondaryText }
            LogosButton {
                text: "logos.dev"
                compact: true
                variant: root.preset === "logos.dev" ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                enabled: root.ready
                onClicked: root.backend.choosePreset("logos.dev")
            }
            LogosButton {
                text: "logos.test"
                compact: true
                variant: root.preset === "logos.test" ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                enabled: root.ready
                onClicked: root.backend.choosePreset("logos.test")
            }
            LogosButton {
                text: "Refresh"
                compact: true
                enabled: root.ready
                onClicked: root.backend.refreshStatus()
            }
        }

        LogosTabBar {
            id: tabs
            objectName: "tabs"
            Layout.fillWidth: true
            LogosTabButton { text: "Create" }
            LogosTabButton { text: "Sent" + (root.sent.length ? "  " + root.sent.length : "") }
            LogosTabButton { text: "Open" + (root.pending.length ? "  " + root.pending.length : "") }
        }

        // ---------------------------------------------------------------- body
        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: tabs.currentIndex

            // ============================================================ Create
            LogosScrollView {
                clip: true
                ColumnLayout {
                    width: Math.max(480, tabs.width)
                    spacing: Theme.spacing.medium

                    // Link panel, shown once after a create
                    LogosFrame {
                        Layout.fillWidth: true
                        visible: root.lastLink !== ""
                        backgroundColor: Theme.palette.surfaceRaised
                        borderColor: Theme.palette.primaryBorder
                        radius: Theme.spacing.radiusLarge
                        padding: Theme.spacing.large
                        contentItem: ColumnLayout {
                            spacing: Theme.spacing.small
                            LogosText { text: "Your link"; font.weight: Theme.typography.weightBold; font.pixelSize: Theme.typography.subtitleText }
                            LogosText {
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                                color: Theme.palette.textSecondary
                                text: "Send this over any channel. Each person who opens it gets the secret once, up to the number of readers you chose, until it expires. Their request reaches this Basecamp when it is running with Onesecret loaded; the network holds each request for about three days and their app keeps asking."
                            }
                            LogosCopyableText {
                                objectName: "linkText"
                                Layout.fillWidth: true
                                text: root.lastLink
                                copyText: root.lastLink
                                textItem.font.family: Theme.typography.mono
                                textItem.font.pixelSize: Theme.typography.secondaryText
                                textItem.wrapMode: TextEdit.WrapAnywhere
                            }
                            RowLayout {
                                spacing: Theme.spacing.small
                                LogosButton {
                                    text: "Copy link and hint"
                                    compact: true
                                    onClicked: hintCopy.copy()
                                }
                                LogosCopyButton {
                                    id: hintCopy
                                    visible: false
                                    value: "One-time secret, open it in the Onesecret app in Logos Basecamp:\n" + root.lastLink
                                }
                                Item { Layout.fillWidth: true }
                                LogosButton {
                                    objectName: "linkDone"
                                    text: "Done"
                                    compact: true
                                    onClicked: root.backend.clearLastLink()
                                }
                            }
                        }
                    }

                    LogosFrame {
                        Layout.fillWidth: true
                        backgroundColor: Theme.palette.surfaceRaised
                        borderColor: Theme.palette.borderSecondary
                        radius: Theme.spacing.radiusLarge
                        padding: Theme.spacing.large
                        contentItem: ColumnLayout {
                            spacing: Theme.spacing.medium

                            LogosText { text: "New secret"; font.weight: Theme.typography.weightBold; font.pixelSize: Theme.typography.subtitleText }

                            LogosTextField {
                                id: nameField
                                objectName: "nameField"
                                Layout.fillWidth: true
                                placeholderText: "Name or hint (encrypted together with the secret)"
                            }
                            LogosTextArea {
                                id: bodyArea
                                objectName: "bodyArea"
                                Layout.fillWidth: true
                                Layout.preferredHeight: 180
                                placeholderText: "The secret. Up to 64 KB of text."
                                font.family: Theme.typography.mono
                                font.pixelSize: Theme.typography.secondaryText
                            }
                            RowLayout {
                                Layout.fillWidth: true
                                LogosText {
                                    color: bodyArea.length > 65536 ? Theme.palette.error : Theme.palette.textTertiary
                                    font.pixelSize: Theme.typography.secondaryText
                                    text: bodyArea.length > 0 ? (bodyArea.length + " characters") : ""
                                }
                                Item { Layout.fillWidth: true }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.spacing.small
                                LogosText { text: "Expires in"; color: Theme.palette.textTertiary; font.pixelSize: Theme.typography.secondaryText }
                                Repeater {
                                    model: root.ttlLabels.length
                                    LogosButton {
                                        required property int index
                                        objectName: "ttlPreset" + index
                                        text: root.ttlLabels[index]
                                        compact: true
                                        variant: !root.ttlCustom && root.ttlIndex === index ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                                        onClicked: { root.ttlCustom = false; root.ttlIndex = index }
                                    }
                                }
                                LogosButton {
                                    objectName: "ttlCustomButton"
                                    text: "Custom"
                                    compact: true
                                    variant: root.ttlCustom ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                                    onClicked: root.ttlCustom = true
                                }
                                Item { Layout.fillWidth: true }
                                LogosText {
                                    objectName: "ttlPreviewText"
                                    color: Theme.palette.textTertiary
                                    font.pixelSize: Theme.typography.secondaryText
                                    text: root.ttlValid ? "until about " + root.ttlPreview : ""
                                }
                            }
                            RowLayout {
                                Layout.fillWidth: true
                                visible: root.ttlCustom
                                spacing: Theme.spacing.small
                                LogosTextField {
                                    id: customTtlField
                                    objectName: "customTtlField"
                                    Layout.preferredWidth: 90
                                    text: String(root.customAmount)
                                    validator: IntValidator { bottom: 1; top: 336 }
                                    onTextChanged: root.customAmount = parseInt(text) || 0
                                }
                                LogosButton {
                                    objectName: "ttlUnitHours"
                                    text: "hours"
                                    compact: true
                                    variant: root.customUnit === "hours" ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                                    onClicked: root.customUnit = "hours"
                                }
                                LogosButton {
                                    objectName: "ttlUnitDays"
                                    text: "days"
                                    compact: true
                                    variant: root.customUnit === "days" ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                                    onClicked: root.customUnit = "days"
                                }
                                LogosText {
                                    color: root.ttlValid ? Theme.palette.textTertiary : Theme.palette.error
                                    font.pixelSize: Theme.typography.secondaryText
                                    text: root.ttlValid ? "" : "Between 1 hour and 14 days."
                                }
                                Item { Layout.fillWidth: true }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.spacing.small
                                LogosText { text: "Readers"; color: Theme.palette.textTertiary; font.pixelSize: Theme.typography.secondaryText }
                                Repeater {
                                    model: root.readerPresets.length
                                    LogosButton {
                                        required property int index
                                        objectName: "readersPreset" + index
                                        text: String(root.readerPresets[index])
                                        compact: true
                                        variant: !root.readersCustom && root.readerIndex === index ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                                        onClicked: { root.readersCustom = false; root.readerIndex = index }
                                    }
                                }
                                LogosButton {
                                    objectName: "readersCustomButton"
                                    text: "Custom"
                                    compact: true
                                    variant: root.readersCustom ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                                    onClicked: root.readersCustom = true
                                }
                                LogosTextField {
                                    objectName: "customReadersField"
                                    visible: root.readersCustom
                                    Layout.preferredWidth: 70
                                    text: String(root.customReaders)
                                    validator: IntValidator { bottom: 1; top: 50 }
                                    onTextChanged: root.customReaders = parseInt(text) || 0
                                }
                                LogosText {
                                    color: root.readersValid ? Theme.palette.textTertiary : Theme.palette.error
                                    font.pixelSize: Theme.typography.secondaryText
                                    text: !root.readersValid ? "Between 1 and 50."
                                        : root.effectiveReaders === 1 ? "one person, once"
                                        : root.effectiveReaders + " different people, once each"
                                }
                                Item { Layout.fillWidth: true }
                            }

                            LogosTextField {
                                id: passField
                                objectName: "passField"
                                Layout.fillWidth: true
                                echoMode: TextInput.Password
                                placeholderText: "Passphrase (optional). Send it over a different channel than the link."
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                LogosText {
                                    Layout.fillWidth: true
                                    wrapMode: Text.Wrap
                                    color: Theme.palette.textTertiary
                                    font.pixelSize: Theme.typography.secondaryText
                                    text: "The secret is encrypted on this machine and stays here until someone opens the link. On the first read this Basecamp destroys its key."
                                }
                                LogosButton {
                                    objectName: "createButton"
                                    text: "Create link"
                                    variant: LogosButton.Variant.Primary
                                    enabled: root.ready && root.ttlValid && root.readersValid && bodyArea.text.trim().length > 0 && bodyArea.length <= 65536
                                    onClicked: root.backend.createSecret(nameField.text, bodyArea.text, root.effectiveTtlHours, passField.text, root.effectiveReaders)
                                }
                            }
                        }
                    }

                    LogosNotice {
                        Layout.fillWidth: true
                        visible: root.lastError !== ""
                        severity: LogosNotice.Error
                        title: "Problem"
                        message: root.lastError
                    }
                }
            }

            // ============================================================ Sent
            ColumnLayout {
                spacing: Theme.spacing.medium
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spacing.small
                    LogosText { text: "Reader names"; color: Theme.palette.textTertiary; font.pixelSize: Theme.typography.secondaryText }
                    LogosButton {
                        objectName: "verifyOff"
                        text: "Off"
                        compact: true
                        variant: root.nameVerify === "off" ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                        enabled: root.ready
                        onClicked: root.backend.chooseNameVerify("off")
                    }
                    LogosButton {
                        objectName: "verifyDns"
                        text: "DNS"
                        compact: true
                        variant: root.nameVerify === "dns" ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                        enabled: root.ready
                        onClicked: root.backend.chooseNameVerify("dns")
                    }
                    LogosButton {
                        objectName: "verifyNames"
                        text: "Logos names"
                        compact: true
                        variant: root.nameVerify === "names" ? LogosButton.Variant.Primary : LogosButton.Variant.Secondary
                        enabled: root.ready
                        onClicked: root.backend.chooseNameVerify("names")
                    }
                    LogosText {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        color: Theme.palette.textTertiary
                        font.pixelSize: Theme.typography.secondaryText
                        text: root.nameVerify === "dns"
                              ? "A reader's domain name is checked against its _onesecret TXT record. Each check is a DNS query your resolver can see. Plain DNS is not authenticated; the tick means DNS-verified."
                              : root.nameVerify === "names"
                                ? "A reader's Logos name is checked through the names module, if it is installed here, against the name's onesecret.key entry. Without the module, names are shown as said."
                                : "Off: a reader's name is shown as said, not checked. No lookups leave this machine."
                    }
                }
                LogosText {
                    visible: root.sent.length === 0
                    color: Theme.palette.textTertiary
                    text: "Nothing shared yet. Secrets you create appear here with their status."
                }
                LogosListView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    spacing: Theme.spacing.small
                    model: root.sent
                    delegate: LogosFrame {
                        required property var modelData
                        width: ListView.view.width
                        backgroundColor: Theme.palette.surfaceRaised
                        borderColor: Theme.palette.borderSecondary
                        radius: Theme.spacing.radiusLarge
                        padding: Theme.spacing.medium
                        contentItem: RowLayout {
                            spacing: Theme.spacing.medium
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2
                                RowLayout {
                                    spacing: Theme.spacing.small
                                    LogosText { text: modelData.name; font.weight: Theme.typography.weightBold; elide: Text.ElideRight; Layout.maximumWidth: 320 }
                                    LogosBadge { text: modelData.label; color: root.ladderColour(modelData.state) }
                                }
                                LogosText {
                                    color: Theme.palette.textTertiary
                                    font.pixelSize: Theme.typography.secondaryText
                                    text: "Created " + modelData.createdAt
                                          + (modelData.live ? "  ·  expires " + modelData.expiresAt : "")
                                          + (modelData.maxReads > 1 ? "  ·  up to " + modelData.maxReads + " readers" : "")
                                }
                                Repeater {
                                    model: modelData.readers
                                    LogosText {
                                        required property var modelData
                                        color: Theme.palette.textTertiary
                                        font.pixelSize: Theme.typography.secondaryText
                                        text: (modelData.openedAt ? "Read " + modelData.openedAt : "Key released " + modelData.releasedAt + ", read not yet confirmed")
                                              + "  ·  device " + modelData.fp
                                              + root.readerName(modelData)
                                              + (modelData.confirmed && !modelData.openedAt ? "  ·  release stored" : "")
                                    }
                                }
                                LogosText {
                                    visible: modelData.state === "done" && modelData.acked < modelData.served
                                    color: Theme.palette.textTertiary
                                    font.pixelSize: Theme.typography.secondaryText
                                    text: "All reads are released and this Basecamp can no longer read the secret. Waiting for the last receipts."
                                }
                            }
                            LogosButton {
                                objectName: "burnButton"
                                visible: modelData.burnable
                                text: "Burn"
                                compact: true
                                onClicked: { root.burnId = modelData.id; root.burnName = modelData.name; root.showBurnConfirm = true }
                            }
                            LogosButton {
                                objectName: "forgetButton"
                                visible: !modelData.burnable
                                text: "Forget"
                                compact: true
                                onClicked: root.backend.forgetSecret(modelData.id)
                            }
                        }
                    }
                }
            }

            // ============================================================ Open
            LogosScrollView {
                clip: true
                ColumnLayout {
                    width: Math.max(480, tabs.width)
                    spacing: Theme.spacing.medium

                    LogosFrame {
                        Layout.fillWidth: true
                        backgroundColor: Theme.palette.surfaceRaised
                        borderColor: Theme.palette.borderSecondary
                        radius: Theme.spacing.radiusLarge
                        padding: Theme.spacing.large
                        contentItem: ColumnLayout {
                            spacing: Theme.spacing.medium
                            LogosText { text: "Open a secret"; font.weight: Theme.typography.weightBold; font.pixelSize: Theme.typography.subtitleText }
                            LogosTextField {
                                id: linkField
                                objectName: "linkField"
                                Layout.fillWidth: true
                                placeholderText: "Paste the link (starts with os1_)"
                                textInput.font.family: Theme.typography.mono
                            }
                            LogosTextField {
                                id: openPassField
                                objectName: "openPassField"
                                Layout.fillWidth: true
                                echoMode: TextInput.Password
                                placeholderText: "Passphrase, if the sender gave you one"
                            }
                            RowLayout {
                                Layout.fillWidth: true
                                LogosText {
                                    Layout.fillWidth: true
                                    wrapMode: Text.Wrap
                                    color: Theme.palette.textTertiary
                                    font.pixelSize: Theme.typography.secondaryText
                                    text: "Opening asks the sender's Basecamp for the key. If it is offline, this app keeps asking (for up to two weeks, whenever it is open) and completes when the sender comes back."
                                }
                                LogosButton {
                                    objectName: "openButton"
                                    text: "Open"
                                    variant: LogosButton.Variant.Primary
                                    enabled: root.ready && linkField.text.trim().length > 0
                                    onClicked: root.backend.openLink(linkField.text, openPassField.text)
                                }
                            }
                        }
                    }

                    LogosFrame {
                        Layout.fillWidth: true
                        backgroundColor: Theme.palette.surfaceRaised
                        borderColor: Theme.palette.borderSecondary
                        radius: Theme.spacing.radiusLarge
                        padding: Theme.spacing.large
                        contentItem: ColumnLayout {
                            spacing: Theme.spacing.small
                            LogosText { text: "How senders see you"; font.weight: Theme.typography.weightBold }
                            LogosSwitch {
                                id: anonSwitch
                                objectName: "anonProfileSwitch"
                                text: "Keep an anonymous profile"
                                checked: root.anonProfile
                                enabled: root.ready && root.myName === ""
                                onToggled: {
                                    root.backend.chooseAnonProfile(checked)
                                    checked = Qt.binding(function() { return root.anonProfile })
                                }
                            }
                            LogosText {
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                                color: Theme.palette.textTertiary
                                font.pixelSize: Theme.typography.secondaryText
                                text: root.myName !== ""
                                      ? "You open links as " + root.myName + "."
                                      : root.anonProfile
                                        ? "Senders see the same anonymous profile each time you open one of their links. It is one profile for every sender, so senders who compare notes can tell they had the same reader."
                                        : "Off: every link you open looks like a different, unknown reader."
                            }
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.spacing.small
                                LogosTextField {
                                    id: myNameField
                                    objectName: "myNameField"
                                    Layout.fillWidth: true
                                    placeholderText: root.myName !== "" ? root.myName : "A domain you control (alice.example.com) or a Logos name (alice)"
                                }
                                LogosButton {
                                    objectName: "myNameSave"
                                    text: "Save"
                                    compact: true
                                    enabled: root.ready && myNameField.text.trim().length > 0
                                    onClicked: { root.backend.chooseName(myNameField.text); myNameField.text = "" }
                                }
                                LogosButton {
                                    objectName: "myNameClear"
                                    visible: root.myName !== ""
                                    text: "Clear"
                                    compact: true
                                    onClicked: root.backend.chooseName("")
                                }
                            }
                            LogosText {
                                visible: root.myName !== ""
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                                color: Theme.palette.textSecondary
                                font.pixelSize: Theme.typography.secondaryText
                                text: root.myNameIsDomain
                                      ? "Senders see \"says " + root.myName + "\" unless they check names by DNS. For that, publish this record once (one record per device):"
                                      : "Senders see \"says " + root.myName + "\" unless they check Logos names. For that, list this Basecamp's reader key on the name once (several devices: several keys, space-separated):"
                            }
                            LogosCopyableText {
                                objectName: "nameRecord"
                                visible: root.nameRecord !== ""
                                Layout.fillWidth: true
                                text: root.nameRecord
                                copyText: root.nameRecord
                                textItem.font.family: Theme.typography.mono
                                textItem.font.pixelSize: Theme.typography.secondaryText
                                textItem.wrapMode: TextEdit.WrapAnywhere
                            }
                            LogosText {
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                                color: Theme.palette.textTertiary
                                font.pixelSize: Theme.typography.secondaryText
                                text: "Your name or profile travels encrypted: only people with the link can read it."
                            }
                        }
                    }

                    LogosNotice {
                        objectName: "openNotice"
                        Layout.fillWidth: true
                        visible: root.openState !== "idle" || root.openInfo !== ""
                        severity: root.openSeverity(root.openState)
                        title: root.openTitle(root.openState)
                        message: root.openInfo
                        actions: [
                            LogosButton {
                                visible: root.openState === "claiming" && root.openId !== ""
                                text: "Cancel this request"
                                compact: true
                                onClicked: root.backend.cancelOpen(root.openId)
                            }
                        ]
                    }

                    LogosText {
                        visible: root.pending.length > 0
                        text: "Waiting on the sender"
                        font.weight: Theme.typography.weightBold
                    }
                    Repeater {
                        model: root.pending
                        LogosFrame {
                            required property var modelData
                            Layout.fillWidth: true
                            backgroundColor: Theme.palette.surfaceRaised
                            borderColor: Theme.palette.borderSecondary
                            radius: Theme.spacing.radiusLarge
                            padding: Theme.spacing.medium
                            contentItem: RowLayout {
                                spacing: Theme.spacing.medium
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 2
                                    LogosText { text: modelData.id; font.family: Theme.typography.mono; font.pixelSize: Theme.typography.secondaryText }
                                    LogosText {
                                        color: Theme.palette.textTertiary
                                        font.pixelSize: Theme.typography.secondaryText
                                        text: (modelData.state === "claiming" ? "Asked " + modelData.beacons + " times since " : "State " + modelData.state + ", since ") + modelData.createdAt
                                    }
                                }
                                LogosButton {
                                    text: "Cancel"
                                    compact: true
                                    onClicked: root.backend.cancelOpen(modelData.id)
                                }
                            }
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------- footer
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spacing.medium
            LogosText {
                Layout.fillWidth: true
                elide: Text.ElideRight
                color: Theme.palette.textTertiary
                font.pixelSize: Theme.typography.secondaryText
                text: root.deliveryInfo
            }
            LogosText {
                color: Theme.palette.textMuted
                font.pixelSize: Theme.typography.secondaryText
                text: (root.keyStore === "keychain" ? "key in Keychain  ·  " : root.keyStore === "file" ? "key in file  ·  " : "") + root.preset
            }
        }
    }

    // ------------------------------------------------------------ burn confirm
    Item {
        anchors.fill: parent
        visible: root.showBurnConfirm
        z: 100
        Rectangle {
            anchors.fill: parent
            color: Theme.palette.scrim
            MouseArea {
                anchors.fill: parent
                // Click-away closes; a click that lands on the dialog itself is
                // ignored here (the dialog's buttons handle their own clicks).
                onClicked: function(mouse) {
                    const p = burnDialog.mapFromItem(parent, mouse.x, mouse.y)
                    if (!burnDialog.contains(Qt.point(p.x, p.y)))
                        root.showBurnConfirm = false
                }
            }
        }
        LogosFrame {
            id: burnDialog
            width: 420
            anchors.centerIn: parent
            backgroundColor: Theme.palette.backgroundSecondary
            borderColor: Theme.palette.border
            radius: Theme.spacing.radiusLarge
            padding: Theme.spacing.xlarge
            contentItem: ColumnLayout {
                spacing: Theme.spacing.medium
                LogosText { text: "Burn this secret?"; font.weight: Theme.typography.weightBold; font.pixelSize: Theme.typography.subtitleText }
                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    color: Theme.palette.textSecondary
                    text: "\"" + root.burnName + "\" will be destroyed now. Anyone who opens the link afterwards is told it was burned. This cannot be undone."
                }
                RowLayout {
                    Layout.fillWidth: true
                    Item { Layout.fillWidth: true }
                    LogosButton { text: "Keep it"; compact: true; onClicked: root.showBurnConfirm = false }
                    LogosButton {
                        objectName: "burnConfirmButton"
                        text: "Burn"
                        compact: true
                        variant: LogosButton.Variant.Primary
                        onClicked: { root.backend.burnSecret(root.burnId); root.showBurnConfirm = false }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------ reveal
    Item {
        anchors.fill: parent
        visible: root.showReveal
        z: 101
        Rectangle {
            anchors.fill: parent
            color: Theme.palette.scrim
            MouseArea { anchors.fill: parent }   // no click-away: closing is deliberate
        }
        LogosFrame {
            width: Math.min(720, root.width - 80)
            anchors.centerIn: parent
            backgroundColor: Theme.palette.backgroundSecondary
            borderColor: Theme.palette.primaryBorder
            radius: Theme.spacing.radiusLarge
            padding: Theme.spacing.xlarge
            contentItem: ColumnLayout {
                spacing: Theme.spacing.medium
                RowLayout {
                    Layout.fillWidth: true
                    LogosText { text: root.revealName; font.weight: Theme.typography.weightBold; font.pixelSize: Theme.typography.subtitleText; elide: Text.ElideRight; Layout.fillWidth: true }
                    LogosBadge { text: "shown once"; color: Theme.palette.warning }
                }
                LogosTextArea {
                    objectName: "revealBody"
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.min(360, Math.max(120, contentHeight + 24))
                    readOnly: true
                    text: root.revealBody
                    font.family: Theme.typography.mono
                    font.pixelSize: Theme.typography.secondaryText
                }
                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    color: Theme.palette.textTertiary
                    font.pixelSize: Theme.typography.secondaryText
                    text: "The sender's copy is being destroyed. When you close this, the text is gone from this app too; copy it first if you need it."
                }
                RowLayout {
                    Layout.fillWidth: true
                    LogosCopyButton { value: root.revealBody }
                    Item { Layout.fillWidth: true }
                    LogosButton {
                        objectName: "revealClose"
                        text: "Close and forget"
                        variant: LogosButton.Variant.Primary
                        compact: true
                        onClicked: {
                            root.showReveal = false
                            root.revealBody = ""
                            root.revealName = ""
                        }
                    }
                }
            }
        }
    }
}
