/*
 * Power Monitor — Benchmark de Cifras Leves
 * Versão final para uso com fonte de bancada ajustável
 *
 * HARDWARE:
 *   INA219 SDA  -> GPIO 21
 *   INA219 SCL  -> GPIO 22
 *   INA219 Vcc  -> 3V3
 *   INA219 GND  -> GND
 *   Pi GPIO 17 (pino físico 11) -> GPIO 4  [sinal de sync]
 *   Pi GND     (pino físico  9) -> GND     [referência do sinal]
 *
 * FONTE DE BANCADA:
 *   Ajustar para 5.10 V antes de ligar a Pi.
 *   Verificar com multímetro nos terminais antes de conectar.
 *
 * BIBLIOTECAS (instalar via Library Manager da Arduino IDE):
 *   - "Adafruit INA219" by Adafruit
 *
 * SAÍDA SERIAL (921600 baud):
 *   timestamp_us,bus_voltage_V,current_mA,power_mW,sync_pin
 */

#include <Wire.h>
#include <Adafruit_INA219.h>

Adafruit_INA219 ina219;

const int     SYNC_PIN            = 4;
const uint32_t SAMPLE_INTERVAL_US = 1000;   // 1 kHz

void setup() {
    Serial.begin(921600);
    while (!Serial) delay(10);

    pinMode(SYNC_PIN, INPUT_PULLDOWN);

    if (!ina219.begin()) {
        Serial.println("# ERRO: INA219 nao detectado. Verifique fiacao I2C.");
        while (1) delay(1000);
    }

    // 32V / 2A: range adequado para Pi 4 (max ~1.5 A)
    ina219.setCalibration_32V_2A();

    Serial.println("# INA219 OK — aguardando dados");
    Serial.println("timestamp_us,bus_voltage_V,current_mA,power_mW,sync_pin");
}

void loop() {
    static uint32_t next_sample = 0;
    uint32_t now = micros();

    if ((int32_t)(now - next_sample) < 0) return;

    float bus_v   = ina219.getBusVoltage_V();
    float current = ina219.getCurrent_mA();
    float power   = ina219.getPower_mW();
    int   sync    = digitalRead(SYNC_PIN);

    Serial.print(now);        Serial.print(',');
    Serial.print(bus_v, 3);   Serial.print(',');
    Serial.print(current, 2); Serial.print(',');
    Serial.print(power, 2);   Serial.print(',');
    Serial.println(sync);

    next_sample += SAMPLE_INTERVAL_US;

    // Realinha se atrasou mais de 5 ms
    if ((int32_t)(micros() - next_sample) > 5000)
        next_sample = micros() + SAMPLE_INTERVAL_US;
}
