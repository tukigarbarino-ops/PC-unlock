#pragma once
// Teclado Bluetooth LE mínimo (HID) sobre NimBLE-Arduino 1.4.x.
#include <Arduino.h>

#define MOD_LCTRL 0x01
#define MOD_LSHIFT 0x02
#define MOD_LALT 0x04
#define MOD_LGUI 0x08

#define HID_KEY_ENTER 0x28
#define HID_KEY_ESC 0x29
#define HID_KEY_SPACE 0x2C
#define HID_KEY_L 0x0F

#define SYS_POWER_DOWN 0x01  // igual que apretar el botón de encendido de la compu
#define SYS_SLEEP 0x02
#define SYS_WAKE 0x04

void kbBegin(const char* name);
void kbLoop();
// Permitir emparejar dispositivos nuevos (solo en modo configuración, o si no hay ninguno).
void kbAllowPairing(bool allow);
int kbBondCount();
void kbForgetAll();
bool kbConnected();
// Aprieta y suelta una tecla (código HID) con modificadores.
void kbTap(uint8_t modifiers, uint8_t key, uint16_t holdMs = 30);
// Escribe un carácter ASCII (distribución US: letras, números y espacio coinciden con la española).
bool kbTypeChar(char c);
// Tecla de sistema (SYS_POWER_DOWN, SYS_SLEEP, SYS_WAKE).
void kbSystem(uint8_t bits);
// Entrada remota ya descifrada (protocolo binario de la vista Remoto). Suelta todo sola a los 2 s sin mensajes.
void kbInput(const uint8_t* data, size_t len);
void kbReleaseAll();
