/*************************************************
 * ESP32-C3 Smart Plug Firmware
 * Transport: HiveMQ Cloud (MQTT over TLS)
 *
 * OTA REMOVED — TLS handshake to HiveMQ was failing with
 * "SSL - Memory allocation failed" / errno 113 because free heap
 * was fragmented (51 KB free but largest contiguous block only
 * ~31 KB; mbedTLS needs a single ~40-45 KB block). ArduinoOTA's
 * UDP listener + mDNS responder were part of that fragmentation
 * pressure, so removing OTA frees up contiguous heap for TLS.
 *
 * NOTE: this firmware no longer supports wireless updates.
 * Re-flash via USB for any future firmware changes, or see the
 * note in mqttTask() about further heap-saving options if TLS
 * still fails after this change.
 *
 * What changed vs Firebase version:
 *  - Firebase_ESP_Client removed entirely
 *  - PubSubClient + WiFiClientSecure replace it
 *  - firebaseTask → mqttTask
 *  - Presence (online/offline) via MQTT LWT — no hacks needed
 *  - Binary packed payloads — minimal wire overhead
 *    • smartplug/cmd    [1 byte]  IN : bits 0-2 = relay3/2/1 target state
 *                                      bit  7   = 1 means "this is a relay cmd"
 *    • smartplug/query  [any]     IN : web publishes anything here to
 *                                      request an on-demand state reply
 *    • smartplug/state  [2 bytes] OUT: byte0=relay bitfield, byte1=RSSI+128
 *                                      sent ONLY on relay change, on query,
 *                                      or right after connecting — no
 *                                      periodic heartbeat anymore
 *    • smartplug/status [1 byte]  OUT: '1'=online LWT ('0'=offline)
 *  - All other tasks (BLE, OTA, button, relay, LED) unchanged
 *************************************************/

#include <Arduino.h>
#include <WiFi.h>
// Must be defined before PubSubClient.h is included
#define MQTT_MAX_PACKET_SIZE 512

#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

/*************************************************
 * !! SECURITY WARNING !!
 * Do NOT commit this file to a public repository.
 *************************************************/
#define WIFI_SSID      "Excitel_3r_2.4G"
#define WIFI_PASSWORD  "1122334466"

/*************************************************
 * HiveMQ Cloud Credentials
 * Free tier: hivemq.com → Create Serverless Cluster
 * Copy the host, then create a username + password
 * under "Access Management".
 *************************************************/
#define MQTT_BROKER    "6f2fc69457734955a223f4a84154f5c5.s1.eu.hivemq.cloud"   // ← paste your cluster host
#define MQTT_PORT      8883                             // TLS port
#define MQTT_USER      "toshaashu09"                  // ← change
#define MQTT_PASS      "Eims@123"                  // ← change
#define MQTT_CLIENT_ID "SmartPlug_ESP32C3"              // must be unique per device


/*************************************************
 * MQTT Topics — Binary Protocol
 *
 * SUB  smartplug/cmd    1 byte  command from app → device
 *   bit 7 (0x80) : must be set — identifies this as a relay command
 *   bit 2 (0x04) : relay 3 target state
 *   bit 1 (0x02) : relay 2 target state
 *   bit 0 (0x01) : relay 1 target state
 *   e.g. 0x83 = 0b10000011 → set relay1=ON relay2=ON relay3=OFF
 *        0x87 = 0b10000111 → all ON
 *        0x80 = 0b10000000 → all OFF
 *
 * PUB  smartplug/state  2 bytes  device → app (sent on every change + heartbeat)
 *   byte 0 : relay bitfield  bit0=relay1 bit1=relay2 bit2=relay3
 *   byte 1 : RSSI encoded    uint8 = (rssi_dBm + 128)
 *            decode: rssi_dBm = byte1 - 128
 *            e.g. -46 dBm → 82,  -90 dBm → 38
 *
 * PUB  smartplug/status 1 byte  LWT presence
 *   0x01 = online   (published on connect)
 *   0x00 = offline  (LWT — broker sends this on disconnect)
 *************************************************/
#define MQTT_TOPIC_STATUS  "smartplug/status"
#define MQTT_TOPIC_CMD     "smartplug/cmd"
#define MQTT_TOPIC_STATE   "smartplug/state"
#define MQTT_TOPIC_QUERY   "smartplug/query"   // web publishes ANY payload here to request a fresh state

// Bit masks for the cmd byte
#define CMD_FLAG_RELAY  0x80   // must be set for relay commands
#define CMD_RELAY1_BIT  0x01
#define CMD_RELAY2_BIT  0x02
#define CMD_RELAY3_BIT  0x04

// Online/offline presence bytes
//
// IMPORTANT: PubSubClient::connect()'s LWT parameter is a `const char*`
// and is measured with strlen() internally — there is no length argument
// for it.  A value of 0x00 is itself the null terminator, so strlen()
// returns 0 and the broker registers an EMPTY LWT payload instead of the
// single byte 0x00.  Any subscriber then receives a 0-length message on
// disconnect, which looks like "no update" rather than "offline" — this
// is exactly why the offline state was never showing up in the browser.
//
// Fix: use printable, non-zero ASCII bytes so strlen() reports 1 and the
// broker forwards a real, non-empty 1-byte payload either way.
#define PRESENCE_ONLINE   0x31   // ASCII '1'
#define PRESENCE_OFFLINE  0x30   // ASCII '0'  (was 0x00 — see note above)

/*************************************************
 * Pin Definitions
 *************************************************/
#define RELAY1_PIN   5
#define RELAY2_PIN   1
#define RELAY3_PIN   3
#define LED_PIN      8
#define BUTTON_PIN   4

/*************************************************
 * NVS (Preferences)
 *************************************************/
#define NVS_NAMESPACE  "sp"
#define NVS_KEY_R0     "r0"
#define NVS_KEY_R1     "r1"
#define NVS_KEY_R2     "r2"

/*************************************************
 * BLE UUIDs (Nordic UART Service)
 *************************************************/
#define BLE_DEVICE_NAME         "SmartPlug"
#define SERVICE_UUID            "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define CHARACTERISTIC_UUID_RX  "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
#define CHARACTERISTIC_UUID_TX  "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"
#define BLE_MTU_PAYLOAD         20

/*************************************************
 * Task Configuration
 *************************************************/
#define WIFI_TASK_PRIORITY    2
#define MQTT_TASK_PRIORITY    3
#define BLE_TASK_PRIORITY     2
#define RELAY_TASK_PRIORITY   3
#define BUTTON_TASK_PRIORITY  3
#define LED_TASK_PRIORITY     1

#define WIFI_TASK_STACK    4096
#define MQTT_TASK_STACK    8192   // TLS on ESP32-C3 needs ≥8 KB stack
#define BLE_TASK_STACK     4096
#define RELAY_TASK_STACK   2048
#define BUTTON_TASK_STACK  2048
#define LED_TASK_STACK     2048

/*************************************************
 * Timing Constants (ms)
 *************************************************/
#define WIFI_CHECK_INTERVAL_MS    1000
#define MQTT_RECONNECT_DELAY_MS     3000   // initial wait between reconnect attempts
#define MQTT_RECONNECT_DELAY_MAX_MS 30000   // cap for exponential backoff
#define MQTT_QUERY_REPLY_DELAY_MS   1000    // delay before replying to a query — server rate-limits messages
#define BLE_SEND_INTERVAL_MS      1000
#define BLE_IDLE_DELAY_MS         100
#define BLE_ADVERTISE_DELAY_MS    500
#define LED_ON_MS                 25
#define LED_OFF_MS                975

/*************************************************
 * Button State Machine Timing (ms)
 *************************************************/
#define BTN_DEBOUNCE_MS    50
#define BTN_INTER_TAP_MS   400
#define BTN_HOLD_MS        2000
#define BTN_MAX_TAPS       3

/*************************************************
 * Relay Command Queue
 *************************************************/
typedef struct {
    uint8_t pin;    // 0-based relay index
    uint8_t state;  // HIGH or LOW
} RelayCommand_t;

QueueHandle_t relayQueue = NULL;
#define RELAY_QUEUE_LENGTH 8

/*************************************************
 * Task Handles
 *************************************************/
TaskHandle_t wifiTaskHandle    = NULL;
TaskHandle_t mqttTaskHandle    = NULL;
TaskHandle_t bleTaskHandle     = NULL;
TaskHandle_t relayTaskHandle   = NULL;
TaskHandle_t buttonTaskHandle  = NULL;
TaskHandle_t ledTaskHandle     = NULL;

/*************************************************
 * MQTT Client
 *************************************************/
static WiFiClientSecure wifiSecureClient;
static PubSubClient     mqttClient(wifiSecureClient);

/*
 * TLS I/O buffer sizes — default is 16 KB Rx + 16 KB Tx = 32 KB total.
 * ESP32-C3 has ~320 KB RAM but BLE alone consumes ~100 KB, WiFi ~80 KB,
 * FreeRTOS tasks ~40 KB, leaving ~100 KB free.  A 32 KB TLS allocation
 * fails because there is no single contiguous 32 KB block available.
 *
 * Shrinking to 4 KB Rx / 2 KB Tx drops the TLS cost to ~6 KB which fits
 * comfortably.  HiveMQ messages are tiny (relay commands, RSSI strings)
 * so the smaller buffers are more than enough.
 */
// MQTT_MAX_PACKET_SIZE 512 — defined above PubSubClient include

/*************************************************
 * BLE State
 *************************************************/
static BLEServer         *pServer           = NULL;
static BLECharacteristic *pTxCharacteristic = NULL;
static volatile bool      deviceConnected    = false;
static volatile bool      oldDeviceConnected = false;

SemaphoreHandle_t bleMutex = NULL;

/*=================================================
 * NVS — Relay State Persistence (via Preferences)
 *================================================*/
static uint8_t relayState[3] = {LOW, LOW, LOW};
SemaphoreHandle_t nvsMutex = NULL;

static void saveRelayState(void) {
    Preferences prefs;
    if (!prefs.begin(NVS_NAMESPACE, false)) {
        Serial.println("[NVS] begin() failed on write");
        return;
    }
    prefs.putUChar(NVS_KEY_R0, relayState[0]);
    prefs.putUChar(NVS_KEY_R1, relayState[1]);
    prefs.putUChar(NVS_KEY_R2, relayState[2]);
    prefs.end();
    Serial.printf("[NVS] Saved  r1=%d r2=%d r3=%d\n",
                  relayState[0], relayState[1], relayState[2]);
}

static bool loadRelayState(void) {
    Preferences prefs;
    if (!prefs.begin(NVS_NAMESPACE, true)) {
        Serial.println("[NVS] begin() failed on read — defaults (all OFF)");
        return false;
    }
    bool exists = prefs.isKey(NVS_KEY_R0);
    if (exists) {
        relayState[0] = prefs.getUChar(NVS_KEY_R0, LOW) ? HIGH : LOW;
        relayState[1] = prefs.getUChar(NVS_KEY_R1, LOW) ? HIGH : LOW;
        relayState[2] = prefs.getUChar(NVS_KEY_R2, LOW) ? HIGH : LOW;
        Serial.printf("[NVS] Loaded  r1=%d r2=%d r3=%d\n",
                      relayState[0], relayState[1], relayState[2]);
    } else {
        Serial.println("[NVS] No saved state — defaults (all OFF)");
    }
    prefs.end();
    return exists;
}

static void applyRelayState(void) {
    digitalWrite(RELAY1_PIN, relayState[0]);
    digitalWrite(RELAY2_PIN, relayState[1]);
    digitalWrite(RELAY3_PIN, relayState[2]);
    Serial.println("[NVS] Relay GPIOs restored from saved state");
}

/*
 * setRelay() — central function for ALL relay changes.
 * Updates GPIO, mirrors relayState[], persists to NVS.
 * pinIndex: 0-based.
 */
static void setRelay(uint8_t pinIndex, uint8_t state) {
    static const uint8_t pins[3] = {RELAY1_PIN, RELAY2_PIN, RELAY3_PIN};
    if (pinIndex >= 3) return;
    state = state ? HIGH : LOW;

    digitalWrite(pins[pinIndex], state);

    if (nvsMutex && xSemaphoreTake(nvsMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        relayState[pinIndex] = state;
        saveRelayState();
        xSemaphoreGive(nvsMutex);
    }
    Serial.printf("[Relay] relay%d = %d\n", pinIndex + 1, state);
}

/*=================================================
 * MQTT Helpers
 *================================================*/

/*
 * publishState()
 * Pack relay bitfield + RSSI into 2 bytes and publish to smartplug/state.
 * Called after any relay change and on the RSSI heartbeat.
 *
 * Wire format:
 *   [0] relay bitfield  bit0=relay1  bit1=relay2  bit2=relay3
 *   [1] RSSI + 128      e.g. -46 dBm → 82
 */
SemaphoreHandle_t mqttMutex = NULL;

// Deferred query-reply state.  We do NOT call publishState() directly
// inside onMqttMessage() — PubSubClient callbacks should stay short and
// non-blocking, and the server expects a delay between messages anyway.
// Instead we record that a reply is owed and let mqttTask's main loop
// send it after MQTT_QUERY_REPLY_DELAY_MS has passed.
static volatile bool     queryPending   = false;
static volatile uint32_t queryReceivedAt = 0;

static void publishState(void) {
    if (!mqttClient.connected()) return;

    uint8_t pkt[2];
    pkt[0] = ((relayState[0] ? 1 : 0)      )   // bit 0
            | ((relayState[1] ? 1 : 0) << 1)    // bit 1
            | ((relayState[2] ? 1 : 0) << 2);   // bit 2

    int rssi = WiFi.RSSI();
    // Clamp to valid range before encoding
    if (rssi < -128) rssi = -128;
    if (rssi >    0) rssi =    0;
    pkt[1] = (uint8_t)(rssi + 128);

    if (mqttMutex && xSemaphoreTake(mqttMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        mqttClient.publish(MQTT_TOPIC_STATE, pkt, sizeof(pkt), /*retain=*/false);
        xSemaphoreGive(mqttMutex);
    }
    Serial.printf("[MQTT] state  relays=0x%02X  rssi=%d dBm (encoded=%d)\n",
                  pkt[0], rssi, pkt[1]);
}

/*
 * syncRelayToMQTT()
 * Called by buttonTask and relayTask after any relay change.
 * Publishes the full packed state (both relay + RSSI) in one shot.
 */
static void syncRelayToMQTT(void) {
    publishState();
}

/*=================================================
 * MQTT Message Callback (runs in mqttTask context)
 *
 * Subscribed topic: smartplug/cmd
 * Payload: exactly 1 byte
 *
 *   bit 7 (0x80) must be set — relay command flag
 *   bit 2 = relay3 target state
 *   bit 1 = relay2 target state
 *   bit 0 = relay1 target state
 *
 * Example: 0x83 = 0b10000011 → relay1=ON relay2=ON relay3=OFF
 *          0x87 = 0b10000111 → all ON
 *          0x80 = 0b10000000 → all OFF
 *================================================*/
static void onMqttMessage(char *topic, byte *payload, unsigned int length) {
    // ── Query topic: any payload schedules a DELAYED state reply.
    //    We don't publish here directly — the callback should stay
    //    short, and the server requires spacing between messages.
    //    mqttTask's main loop sends the actual reply after
    //    MQTT_QUERY_REPLY_DELAY_MS has elapsed.
    if (strcmp(topic, MQTT_TOPIC_QUERY) == 0) {
        Serial.println("[MQTT] Query received — reply scheduled");
        queryReceivedAt = millis();
        queryPending    = true;
        return;
    }

    // ── Relay command topic ─────────────────────────────────────────
    if (length == 0) return;

    Serial.printf("[MQTT] cmd  topic=%s  byte=0x%02X\n", topic, payload[0]);

    if (!(payload[0] & CMD_FLAG_RELAY)) {
        Serial.println("[MQTT] Ignored — command flag (bit7) not set");
        return;
    }

    const uint8_t masks[3] = { CMD_RELAY1_BIT, CMD_RELAY2_BIT, CMD_RELAY3_BIT };
    for (uint8_t i = 0; i < 3; i++) {
        uint8_t newState = (payload[0] & masks[i]) ? HIGH : LOW;
        if (newState != relayState[i]) {
            RelayCommand_t cmd = {i, newState};
            xQueueSend(relayQueue, &cmd, 0);
            Serial.printf("[MQTT] relay%d → %d\n", i + 1, newState);
        }
    }
}

/*=================================================
 * MQTT Connect / Reconnect
 *
 * LWT (Last Will Testament) is registered here.
 * The broker publishes "offline" to smartplug/status
 * automatically the moment our TCP connection drops —
 * even on power cut or crash.  No polling needed.
 *================================================*/
static bool mqttConnect(void) {
    // ── Force-close any stale socket before retrying ───────────────
    // If a previous TLS handshake aborted partway (errno 113 / -32512),
    // the underlying WiFiClientSecure socket can be left in a half-open
    // state. Calling connect() again WITHOUT first closing it reuses
    // that broken file descriptor, and after enough failed attempts
    // lwIP runs out of free sockets entirely — which is what produces
    // repeated "Software caused connection abort" (errno 113) even
    // though WiFi itself is fine (note the IP/RSSI print right before
    // the error in the log — WiFi was never the problem).
    //
    // mqttClient.disconnect() tells PubSubClient to clean up state;
    // wifiSecureClient.stop() forces the actual TCP/TLS socket closed
    // regardless of what state it thinks it's in.
    mqttClient.disconnect();
    wifiSecureClient.stop();
    vTaskDelay(pdMS_TO_TICKS(100));   // give lwIP a moment to release the fd

    // Diagnostic: TLS handshake needs a contiguous block of free heap.
    // If this number is trending down over time/reconnects, or drops
    // below ~40000 right before a failed attempt, the root cause is
    // heap fragmentation/exhaustion rather than a network issue.
    Serial.printf("[MQTT] Free heap before connect: %u bytes (largest block: %u)\n",
                  ESP.getFreeHeap(), ESP.getMaxAllocHeap());

    Serial.printf("[MQTT] Connecting to %s:%d …\n", MQTT_BROKER, MQTT_PORT);

    // LWT payload: ASCII '0' (0x30) = offline.
    // Cast to const char* is now SAFE because the byte is non-zero,
    // so strlen() correctly measures it as length 1 — see comment
    // on PRESENCE_OFFLINE above for why 0x00 could not be used here.
    const char *lwtPayload = "0";   // ASCII '0' == PRESENCE_OFFLINE == 0x30
    bool ok = mqttClient.connect(
        MQTT_CLIENT_ID,
        MQTT_USER,
        MQTT_PASS,
        MQTT_TOPIC_STATUS,   // LWT topic
        1,                   // LWT QoS 1
        true,                // LWT retain
        lwtPayload,          // LWT payload — broker sends '0' (0x30) on disconnect
        false                // cleanSession
    );

    if (!ok) {
        Serial.printf("[MQTT] Connect failed, rc=%d\n", mqttClient.state());
        return false;
    }

    // Publish ASCII '1' (0x31) = online — overwrites the retained LWT '0'
    uint8_t onlinePayload = PRESENCE_ONLINE;
    mqttClient.publish(MQTT_TOPIC_STATUS, &onlinePayload, 1, /*retain=*/true);

    // Command topic + query topic
    mqttClient.subscribe(MQTT_TOPIC_CMD,   1);
    mqttClient.subscribe(MQTT_TOPIC_QUERY, 1);

    // Publish full packed state once on connect so a web page that's
    // already open and subscribed gets an immediate sync without
    // needing to send a query itself.
    publishState();

    Serial.println("[MQTT] Connected — subscribed to cmd + query topics");
    return true;
}

/*=================================================
 * BLE Callbacks
 *================================================*/
class MyServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer *pSrv) override    { deviceConnected = true;  }
    void onDisconnect(BLEServer *pSrv) override { deviceConnected = false; }
};

class MyCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *pCharacteristic) override {
        String rxValue = pCharacteristic->getValue();
        if (rxValue.length() == 0) return;

        Serial.print("[BLE RX] ");
        Serial.println(rxValue);

        // Multi-token parser: "R1:1 R2:0 R3:1" or individual "R1:1"
        const char *p   = rxValue.c_str();
        const char *end = p + rxValue.length();
        while (p <= end - 4) {
            if (p[0] == 'R' && p[2] == ':' &&
                p[1] >= '1' && p[1] <= '3' &&
                (p[3] == '0' || p[3] == '1'))
            {
                uint8_t idx   = p[1] - '1';
                uint8_t state = (p[3] == '1') ? HIGH : LOW;
                RelayCommand_t cmd = {idx, state};
                xQueueSend(relayQueue, &cmd, 0);
                Serial.printf("[BLE] R%d -> %d\n", idx + 1, state);
                p += 4;
            } else {
                p++;
            }
        }
    }
};

/*=================================================
 * BLE Write Helpers
 *================================================*/
static void bleWriteRaw(const char *buf, size_t len) {
    pTxCharacteristic->setValue((uint8_t *)buf, len);
    pTxCharacteristic->notify();
    vTaskDelay(pdMS_TO_TICKS(10));
}

static void bleWrite(const String &out) {
    if (!bleMutex) return;
    if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(100)) != pdTRUE) return;
    if (deviceConnected) {
        const char *data      = out.c_str();
        size_t      remaining = out.length();
        size_t      offset    = 0;
        while (remaining > 0) {
            size_t chunk = (remaining > BLE_MTU_PAYLOAD) ? BLE_MTU_PAYLOAD : remaining;
            bleWriteRaw(data + offset, chunk);
            offset    += chunk;
            remaining -= chunk;
        }
    }
    xSemaphoreGive(bleMutex);
}

static void bleWriteln(const String &out) { bleWrite(out + "\n"); }

/*=================================================
 * BLE Initialisation
 *================================================*/
static void BLEInit(void) {
    BLEDevice::init(BLE_DEVICE_NAME);

    pServer = BLEDevice::createServer();
    if (!pServer) { Serial.println("[BLE] Server create failed"); delay(1000); ESP.restart(); }
    pServer->setCallbacks(new MyServerCallbacks());

    BLEService *pService = pServer->createService(SERVICE_UUID);

    pTxCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_UUID_TX, BLECharacteristic::PROPERTY_NOTIFY);
    if (!pTxCharacteristic) { Serial.println("[BLE] TX char failed"); delay(1000); ESP.restart(); }
    pTxCharacteristic->addDescriptor(new BLE2902());

    BLECharacteristic *pRxCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_UUID_RX, BLECharacteristic::PROPERTY_WRITE);
    if (!pRxCharacteristic) { Serial.println("[BLE] RX char failed"); delay(1000); ESP.restart(); }
    pRxCharacteristic->setCallbacks(new MyCallbacks());

    pService->start();
    pServer->getAdvertising()->start();
    Serial.println("[BLE] Advertising — waiting for client");
}

/*=================================================
 * WiFi Helpers
 *================================================*/
static void connectWiFi(void) {
    WiFi.mode(WIFI_STA);
    WiFi.setTxPower(WIFI_POWER_5dBm);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    Serial.print("[WiFi] Connecting");
    uint8_t attempts = 0;
    while (WiFi.status() != WL_CONNECTED) {
        Serial.print(".");
        vTaskDelay(pdMS_TO_TICKS(500));
        if (++attempts > 120) {
            Serial.println("\n[WiFi] Timeout — retrying without restart");
            WiFi.disconnect(false);
            vTaskDelay(pdMS_TO_TICKS(1000));
            WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
            attempts = 0;
        }
    }
    Serial.printf("\n[WiFi] IP=%s  RSSI=%d dBm\n",
                  WiFi.localIP().toString().c_str(), WiFi.RSSI());
}

/*=================================================
 * Relay Task
 * Drains relay command queue — runs immediately on
 * boot with no WiFi dependency, so BLE commands work
 * even when offline.  After setRelay(), publishes new
 * state to MQTT broker if connected.
 *================================================*/
void relayTask(void *pvParameters) {
    while (1) {
        RelayCommand_t cmd;
        while (xQueueReceive(relayQueue, &cmd, 0) == pdTRUE) {
            setRelay(cmd.pin, cmd.state);
            publishState();               // packed 2-byte state — no-op if not connected
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

/*=================================================
 * FreeRTOS Tasks
 *================================================*/

/* --- WiFi Task --- */
void wifiTask(void *pvParameters) {
    connectWiFi();
    while (1) {
        if (WiFi.status() != WL_CONNECTED) {
            Serial.println("[WiFi] Lost — reconnecting");
            connectWiFi();
        }
        vTaskDelay(pdMS_TO_TICKS(WIFI_CHECK_INTERVAL_MS));
    }
}

/* --- MQTT Task ---
 * Replaces firebaseTask entirely.
 * Responsibilities:
 *   1. Wait for WiFi
 *   2. Configure TLS (setInsecure = skip cert verify; see note below)
 *   3. Connect to broker with LWT
 *   4. Call mqttClient.loop() every 10 ms to process inbound messages
 *      (relay commands AND on-demand status queries)
 *   5. Reconnect automatically on disconnect
 *
 * No periodic RSSI/state heartbeat — the device stays silent unless
 * a relay changes or the web app explicitly asks via smartplug/query.
 * This cuts broker traffic significantly when nobody has the page open.
 *
 * TLS note: setInsecure() skips server certificate verification.
 * For production, load the HiveMQ root CA instead:
 *   wifiSecureClient.setCACert(HIVEMQ_ROOT_CA);   // PEM string
 * The root CA PEM can be downloaded from your HiveMQ Cloud console.
 */
void mqttTask(void *pvParameters) {
    // Wait for WiFi
    while (WiFi.status() != WL_CONNECTED)
        vTaskDelay(pdMS_TO_TICKS(500));

    // On ESP32 the TLS stack is mbedTLS — setBufferSizes() is ESP8266-only
    // and does not exist here.  The correct way to reduce heap pressure is:
    //
    //   1. Use MQTT_MAX_PACKET_SIZE 512 (defined before PubSubClient include)
    //      — keeps PubSubClient's internal buffer small.
    //
    //   2. Call setInsecure() which skips loading the full CA bundle,
    //      saving ~10 KB of heap vs setCACert().
    //
    //   3. The MQTT_TASK_STACK of 8192 gives mbedTLS enough stack for the
    //      TLS handshake without spilling into heap.
    //
    // Together these three measures drop peak TLS heap use from ~32 KB to
    // ~12 KB which fits alongside BLE on the ESP32-C3.
    wifiSecureClient.setInsecure();   // skip cert verify (use setCACert for prod)

    mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
    mqttClient.setCallback(onMqttMessage);
    mqttClient.setKeepAlive(30);           // send PINGREQ every 30 s
    mqttClient.setSocketTimeout(10);       // 10 s socket timeout

    // No periodic heartbeat anymore — publishState() is now only called:
    //   1. once right after connecting        (mqttConnect)
    //   2. whenever a relay actually changes   (relayTask, buttonTask)
    //   3. whenever the web page asks for it   (onMqttMessage / query topic)
    while (1) {
        // ── Reconnect loop with exponential backoff ─────────────
        // A fixed 3 s retry hammers a struggling socket/broker
        // connection repeatedly, which can make a transient heap or
        // socket-exhaustion issue (errno 113) worse instead of letting
        // it recover. Backing off doubles the wait each failure, up
        // to MQTT_RECONNECT_DELAY_MAX_MS, then resets once connected.
        if (!mqttClient.connected()) {
            Serial.println("[MQTT] Disconnected — reconnecting…");
            uint32_t backoff = MQTT_RECONNECT_DELAY_MS;

            while (!mqttConnect()) {
                Serial.printf("[MQTT] Retry in %u ms\n", backoff);
                vTaskDelay(pdMS_TO_TICKS(backoff));

                backoff = (backoff * 2 > MQTT_RECONNECT_DELAY_MAX_MS)
                          ? MQTT_RECONNECT_DELAY_MAX_MS
                          : backoff * 2;

                while (WiFi.status() != WL_CONNECTED)
                    vTaskDelay(pdMS_TO_TICKS(500));
            }
        }

        // ── Process inbound messages (cmd + query) ──────────────
        if (mqttMutex && xSemaphoreTake(mqttMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            mqttClient.loop();
            xSemaphoreGive(mqttMutex);
        }

        // ── Send delayed query reply, if one is owed and due ────
        if (queryPending && (millis() - queryReceivedAt >= MQTT_QUERY_REPLY_DELAY_MS)) {
            queryPending = false;
            publishState();
            Serial.println("[MQTT] Query reply sent (after delay)");
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/* --- BLE Task --- */
void bleTask(void *pvParameters) {
    while (1) {
        bool connected    = deviceConnected;
        bool oldConnected = oldDeviceConnected;

        if (connected) {
            String out = "R1:" + String(relayState[0]) +
                         " R2:" + String(relayState[1]) +
                         " R3:" + String(relayState[2]);
            bleWriteln(out);
            vTaskDelay(pdMS_TO_TICKS(BLE_SEND_INTERVAL_MS));
        } else {
            vTaskDelay(pdMS_TO_TICKS(BLE_IDLE_DELAY_MS));
        }

        if (!connected && oldConnected) {
            vTaskDelay(pdMS_TO_TICKS(BLE_ADVERTISE_DELAY_MS));
            if (bleMutex && xSemaphoreTake(bleMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                pServer->startAdvertising();
                oldDeviceConnected = false;
                xSemaphoreGive(bleMutex);
            }
            Serial.println("[BLE] Advertising restarted");
        }
        if (connected && !oldConnected) {
            oldDeviceConnected = true;
            Serial.println("[BLE] Client connected");
        }
    }
}

/*=================================================
 * Button Task — Tap + Hold State Machine
 *  1 tap  + hold 2 s → toggle Relay 1
 *  2 taps + hold 2 s → toggle Relay 2
 *  3 taps + hold 2 s → toggle Relay 3
 *================================================*/
typedef enum {
    BTN_IDLE,
    BTN_DEBOUNCE,
    BTN_COUNTING,
    BTN_HOLD_WAIT,
    BTN_EXECUTE,
} BtnState_t;

void buttonTask(void *pvParameters) {
    pinMode(BUTTON_PIN, INPUT_PULLUP);

    BtnState_t state    = BTN_IDLE;
    uint8_t    tapCount = 0;
    uint32_t   stateTs  = 0;

    while (1) {
        bool     pressed = (digitalRead(BUTTON_PIN) == LOW);
        uint32_t now     = millis();

        switch (state) {
            case BTN_IDLE:
                if (pressed) { tapCount = 0; stateTs = now; state = BTN_DEBOUNCE; }
                break;

            case BTN_DEBOUNCE:
                if (now - stateTs >= BTN_DEBOUNCE_MS) {
                    if (pressed) { tapCount = 1; stateTs = now; state = BTN_HOLD_WAIT;
                                   Serial.printf("[BTN] tap=%d\n", tapCount); }
                    else         { state = BTN_IDLE; }
                }
                break;

            case BTN_COUNTING:
                if (pressed) {
                    if (tapCount < BTN_MAX_TAPS) tapCount++;
                    stateTs = now; state = BTN_HOLD_WAIT;
                    Serial.printf("[BTN] tap=%d\n", tapCount);
                } else if (now - stateTs >= BTN_INTER_TAP_MS) {
                    Serial.println("[BTN] Cancelled (no hold)");
                    state = BTN_IDLE;
                }
                break;

            case BTN_HOLD_WAIT:
                if (!pressed)                          { stateTs = now; state = BTN_COUNTING; }
                else if (now - stateTs >= BTN_HOLD_MS) { state = BTN_EXECUTE; }
                break;

            case BTN_EXECUTE: {
                uint8_t idx = tapCount - 1;
                if (idx < 3) {
                    uint8_t newState = relayState[idx] ? LOW : HIGH;
                    setRelay(idx, newState);
                    syncRelayToMQTT();       // publish packed 2-byte state
                    Serial.printf("[BTN] Relay%d → %d\n", idx + 1, newState);
                } else {
                    Serial.printf("[BTN] Invalid tap count %d — ignored\n", tapCount);
                }
                tapCount = 0;
                while (digitalRead(BUTTON_PIN) == LOW) vTaskDelay(pdMS_TO_TICKS(10));
                state = BTN_IDLE;
                break;
            }
            default: state = BTN_IDLE; break;
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/* --- LED Task --- */
void ledTask(void *pvParameters) {
    while (1) {
        digitalWrite(LED_PIN, HIGH); vTaskDelay(pdMS_TO_TICKS(LED_ON_MS));
        digitalWrite(LED_PIN, LOW);  vTaskDelay(pdMS_TO_TICKS(LED_OFF_MS));
    }
}

/*=================================================
 * Setup
 *================================================*/
void setup() {
    Serial.begin(115200);

    pinMode(RELAY1_PIN, OUTPUT); digitalWrite(RELAY1_PIN, LOW);
    pinMode(RELAY2_PIN, OUTPUT); digitalWrite(RELAY2_PIN, LOW);
    pinMode(RELAY3_PIN, OUTPUT); digitalWrite(RELAY3_PIN, LOW);
    pinMode(LED_PIN,    OUTPUT); digitalWrite(LED_PIN,    LOW);
    pinMode(BUTTON_PIN, INPUT_PULLUP);

    // NVS mutex + load saved relay state before any task starts
    nvsMutex = xSemaphoreCreateMutex();
    if (!nvsMutex) { Serial.println("[Setup] nvsMutex failed"); delay(1000); ESP.restart(); }
    loadRelayState();
    applyRelayState();

    // MQTT mutex (serialises publish calls across tasks)
    mqttMutex = xSemaphoreCreateMutex();
    if (!mqttMutex) { Serial.println("[Setup] mqttMutex failed"); delay(1000); ESP.restart(); }

    // Relay command queue
    relayQueue = xQueueCreate(RELAY_QUEUE_LENGTH, sizeof(RelayCommand_t));
    if (!relayQueue) { Serial.println("[Setup] relayQueue failed"); delay(1000); ESP.restart(); }

    // BLE mutex
    bleMutex = xSemaphoreCreateMutex();
    if (!bleMutex) { Serial.println("[Setup] bleMutex failed"); delay(1000); ESP.restart(); }

    BLEInit();

    xTaskCreate(relayTask,  "RelayTask",  RELAY_TASK_STACK,  NULL, RELAY_TASK_PRIORITY,  &relayTaskHandle);
    xTaskCreate(wifiTask,   "WiFiTask",   WIFI_TASK_STACK,   NULL, WIFI_TASK_PRIORITY,   &wifiTaskHandle);
    xTaskCreate(mqttTask,   "MQTTTask",   MQTT_TASK_STACK,   NULL, MQTT_TASK_PRIORITY,   &mqttTaskHandle);
    xTaskCreate(bleTask,    "BLETask",    BLE_TASK_STACK,    NULL, BLE_TASK_PRIORITY,    &bleTaskHandle);
    xTaskCreate(buttonTask, "ButtonTask", BUTTON_TASK_STACK, NULL, BUTTON_TASK_PRIORITY, &buttonTaskHandle);
    xTaskCreate(ledTask,    "LEDTask",    LED_TASK_STACK,    NULL, LED_TASK_PRIORITY,    &ledTaskHandle);

    vTaskDelete(NULL);
}

/*=================================================
 * Loop — not used
 *================================================*/
void loop() {
    vTaskDelay(portMAX_DELAY);
}