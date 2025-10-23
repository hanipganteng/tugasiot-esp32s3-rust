// Atribut untuk lingkungan no-std/embedded
#![no_std]
#![no_main]

// Import dari library C esp-idf secara langsung
use esp_idf_sys::*;

// Import untuk hardware, service, dan WiFi dari pustaka Rust tingkat tinggi
use esp_idf_hal::{delay::Ets, peripherals::Peripherals, gpio::PinDriver};
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    nvs::EspDefaultNvsPartition,
    wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi},
    sntp::{EspSntp, SyncStatus},
};

// Import untuk sensor dan logging
use embedded_dht_rs::dht22::Dht22;
use log::{error, info};

// Import untuk penanganan error dan JSON
use anyhow::{Result, anyhow};
use serde_json::json;

// Import yang diperlukan untuk berinteraksi dengan C (string)
use alloc::string::ToString;
use alloc::ffi::CString;
use core::ffi::c_char;

// Deklarasi bahwa kita akan menggunakan alokator memori
extern crate alloc;

// --- KONFIGURASI ---
const WIFI_SSID: &str = "LANCAR JAYA";
const WIFI_PASS: &str = "jaya12345";
const MQTT_BROKER: &str = "mqtt://mqtt.thingsboard.cloud:1883";
const THINGSBOARD_TOKEN: &str = "pNQ4wOKQOY9tUPQHaz7H";

// Helper function konversi waktu delay
#[inline(always)]
fn ms_to_ticks(ms: u32) -> u32 {
    (ms as u64 * configTICK_RATE_HZ as u64 / 1000) as u32
}

// Struct klien MQTT
struct SimpleMqttClient {
    client: *mut esp_mqtt_client,
    _broker_url: CString,
    _username: CString,
    _password: CString,
    _client_id: CString,
}

impl SimpleMqttClient {
    fn new(broker_url: &str, username: &str, password: &str, client_id: &str) -> Result<Self> {
        unsafe {
            let broker_url_cstr = CString::new(broker_url)?;
            let username_cstr = CString::new(username)?;
            let password_cstr = CString::new(password)?;
            let client_id_cstr = CString::new(client_id)?;

            let config = esp_mqtt_client_config_t {
                broker: esp_mqtt_client_config_t_broker_t {
                    address: esp_mqtt_client_config_t_broker_t_address_t {
                        uri: broker_url_cstr.as_ptr(),
                        ..core::mem::zeroed()
                    },
                    ..core::mem::zeroed()
                },
                credentials: esp_mqtt_client_config_t_credentials_t {
                    username: username_cstr.as_ptr(),
                    client_id: client_id_cstr.as_ptr(),
                    authentication: esp_mqtt_client_config_t_credentials_t_authentication_t {
                        password: password_cstr.as_ptr(),
                        ..core::mem::zeroed()
                    },
                    ..core::mem::zeroed()
                },
                // --- PERBAIKAN FINAL DI SINI ---
                // Menggunakan nama struct yang benar sesuai petunjuk compiler
                network: esp_mqtt_client_config_t_network_t {
                    timeout_ms: 5000,
                    ..core::mem::zeroed()
                },
                ..core::mem::zeroed()
            };

            let client = esp_mqtt_client_init(&config as *const _);
            if client.is_null() {
                return Err(anyhow::anyhow!("Gagal menginisialisasi klien MQTT"));
            }
            let err = esp_mqtt_client_start(client);
            if err != ESP_OK {
                return Err(anyhow::anyhow!("Gagal memulai klien MQTT, kode error: {}", err));
            }
            vTaskDelay(ms_to_ticks(2000));
            Ok(Self {
                client,
                _broker_url: broker_url_cstr,
                _username: username_cstr,
                _password: password_cstr,
                _client_id: client_id_cstr,
            })
        }
    }

    fn publish(&self, topic: &str, data: &str, qos: i32) -> Result<()> {
        unsafe {
            let topic_cstr = CString::new(topic)?;
            let payload_cstr = CString::new(data)?;
            let payload_len = payload_cstr.as_bytes().len() as i32;
            let msg_id = esp_mqtt_client_publish(self.client, topic_cstr.as_ptr(), payload_cstr.as_ptr() as *const c_char, payload_len, qos, 0);
            if msg_id < 0 {
                Err(anyhow!("Gagal mempublikasikan pesan, kode error: {}", msg_id))
            } else {
                info!("Pesan diantrekan untuk dikirim dengan ID: {}", msg_id);
                Ok(())
            }
        }
    }
}

impl Drop for SimpleMqttClient {
    fn drop(&mut self) {
        unsafe {
            esp_mqtt_client_stop(self.client);
            esp_mqtt_client_destroy(self.client);
            info!("Klien MQTT dihentikan dan dibersihkan.");
        }
    }
}

#[no_mangle]
fn main() {
    esp_idf_sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    
    info!("🚀 MEMULAI PROGRAM ESP32S3 DHT22 + WiFi + MQTT (Versi Tangguh)");

    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs)).unwrap(),
        sys_loop,
    ).unwrap();

    match connect_wifi(&mut wifi) {
        Ok(_) => info!("✅ Koneksi WiFi Awal Berhasil."),
        Err(e) => {
            error!("❌ Gagal melakukan koneksi WiFi awal: {:?}, program berhenti.", e);
            return;
        }
    };
    
    info!("🕒 Menginisialisasi service SNTP...");
    let sntp = EspSntp::new_default().unwrap();
    info!("🕒 Menunggu sinkronisasi waktu...");
    while sntp.get_sync_status() != SyncStatus::Completed {
        unsafe { vTaskDelay(ms_to_ticks(100)); }
    }
    info!("✅ Sinkronisasi waktu berhasil.");

    info!("Menghubungkan ke broker MQTT ThingsBoard...");
    let mut mqtt_client: Option<SimpleMqttClient> = None;

    match SimpleMqttClient::new(MQTT_BROKER, THINGSBOARD_TOKEN, "", "") {
        Ok(client) => {
            info!("✅ Terhubung ke broker MQTT ThingsBoard.");
            mqtt_client = Some(client);
        }
        Err(e) => {
            error!("❌ Gagal terhubung ke MQTT: {:?}", e);
        }
    };

    let pin = PinDriver::input_output_od(peripherals.pins.gpio4).unwrap();
    let delay = Ets;
    let mut dht22 = Dht22::new(pin, delay);
    
    loop {
        if wifi.is_connected().unwrap_or(false) {
            
            if mqtt_client.is_none() {
                info!("Mencoba menyambung kembali ke MQTT...");
                if let Ok(client) = SimpleMqttClient::new(MQTT_BROKER, THINGSBOARD_TOKEN, "", "") {
                    info!("✅ Koneksi ulang MQTT berhasil.");
                    mqtt_client = Some(client);
                } else {
                    error!("Gagal menyambung kembali ke MQTT, akan coba lagi nanti.");
                }
            }

            if let Some(client) = &mqtt_client {
                match dht22.read() {
                    Ok(reading) => {
                        info!("🌡️ Temp: {:.2} °C, 💧 Hum: {:.2} %", reading.temperature, reading.humidity);
                        let current_ts_seconds = unsafe { esp_idf_sys::time(core::ptr::null_mut()) } as u64;
                        let current_ts_millis = current_ts_seconds * 1000;
                        let payload = json!({
                            "ts": current_ts_millis,
                            "values": { "temperature": reading.temperature, "humidity": reading.humidity }
                        }).to_string();

                        match client.publish("v1/devices/me/telemetry", &payload, 1) {
                            Ok(_) => info!("📡 Telemetri terkirim: {}", payload),
                            Err(e) => {
                                error!("❌ Gagal mengirim telemetri (timeout/error): {:?}.", e);
                                mqtt_client = None; 
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ Gagal membaca DHT22: {:?}", e);
                    }
                }
            }
        } else {
            error!("❌ Koneksi WiFi terputus. Mencoba menyambung kembali...");
            mqtt_client = None; 
            if let Err(e) = connect_wifi(&mut wifi) {
                error!("Gagal menyambung kembali ke WiFi: {:?}", e);
            } else {
                info!("✅ Berhasil menyambung kembali ke WiFi.");
            }
        }
        
        unsafe {
            vTaskDelay(ms_to_ticks(7000));
        }
    }
}

fn connect_wifi(wifi: &mut BlockingWifi<EspWifi<'static>>) -> Result<()> {
    info!("Menghubungkan ke WiFi SSID: {}", WIFI_SSID);

    let wifi_config = Configuration::Client(ClientConfiguration {
        ssid: heapless::String::try_from(WIFI_SSID)
            .map_err(|_| anyhow!("Hanipo"))?,
        password: heapless::String::try_from(WIFI_PASS)
            .map_err(|_| anyhow!("tes12345"))?,
        auth_method: AuthMethod::WPA2Personal,
        ..Default::default()
    });

    wifi.set_configuration(&wifi_config)?;
    wifi.start()?;
    info!("Memindai dan mencoba terhubung...");
    wifi.connect()?;
    info!("Menunggu konfirmasi IP dari jaringan...");
    wifi.wait_netif_up()?;

    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;
    info!("Mendapat IP: {}", ip_info.ip);

    Ok(())
}