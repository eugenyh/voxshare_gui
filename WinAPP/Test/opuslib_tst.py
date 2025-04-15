import opuslib
import array
import os

# --- Параметры аудио ---
SAMPLE_RATE = 48000  # Частота дискретизации (Гц). Opus поддерживает 8, 12, 16, 24, 48 кГц
CHANNELS = 1         # Количество каналов (1 для моно, 2 для стерео)
FRAME_DURATION_MS = 20  # Длительность одного фрейма в миллисекундах (обычно 20, 40, 60)
# Рассчитываем количество сэмплов в одном фрейме
SAMPLES_PER_FRAME = int(SAMPLE_RATE * FRAME_DURATION_MS / 1000)
# Размер сэмпла в байтах (16 бит = 2 байта)
BYTES_PER_SAMPLE = 2
# Размер PCM данных для одного фрейма в байтах
PCM_FRAME_SIZE = SAMPLES_PER_FRAME * CHANNELS * BYTES_PER_SAMPLE

# --- Данные для примера ---
# Создадим немного "сырых" PCM данных (тишина) для одного фрейма
# В реальном приложении вы бы читали данные из файла или аудиоустройства
# Данные должны быть в формате signed 16-bit little-endian PCM
pcm_data = b'\x00' * PCM_FRAME_SIZE
# Для демонстрации можно использовать 'array' для создания данных
# import math
# pcm_array = array.array('h') # 'h' = signed short (16-bit)
# for i in range(SAMPLES_PER_FRAME * CHANNELS):
#     # Простая синусоида для примера
#     value = int(math.sin(i / (SAMPLES_PER_FRAME / 10) * 2 * math.pi) * 16384)
#     pcm_array.append(value)
# pcm_data = pcm_array.tobytes()


print(f"Параметры звука:")
print(f"  Частота дискретизации: {SAMPLE_RATE} Гц")
print(f"  Каналы: {CHANNELS}")
print(f"  Длительность фрейма: {FRAME_DURATION_MS} мс")
print(f"  Сэмплов на фрейм: {SAMPLES_PER_FRAME}")
print(f"  Ожидаемый размер PCM фрейма: {PCM_FRAME_SIZE} байт")
print(f"  Размер сгенерированных PCM данных: {len(pcm_data)} байт")

# --- Инициализация кодера и декодера ---
try:
    # Создание экземпляра кодера
    # opuslib.APPLICATION_AUDIO - режим для музыки/общего звука
    # opuslib.APPLICATION_VOIP - режим для голоса
    # opuslib.APPLICATION_LOWDELAY - режим с низкой задержкой
    encoder = opuslib.Encoder(SAMPLE_RATE, CHANNELS, opuslib.APPLICATION_AUDIO)
    print("\nOpus кодер успешно создан.")

    # Создание экземпляра декодера
    decoder = opuslib.Decoder(SAMPLE_RATE, CHANNELS)
    print("Opus декодер успешно создан.")

    # --- Кодирование ---
    print("\nКодирование PCM данных...")
    # Кодируем один фрейм PCM данных
    # Второй аргумент - количество сэмплов *на канал* во фрейме
    encoded_data = encoder.encode(pcm_data, SAMPLES_PER_FRAME)
    print(f"Размер закодированных данных (Opus пакет): {len(encoded_data)} байт")

    # --- Декодирование ---
    print("\nДекодирование Opus пакета...")
    # Декодируем Opus пакет обратно в PCM
    # Второй аргумент - ожидаемое количество сэмплов *на канал* в выходном фрейме
    # Третий аргумент (decode_fec) - использовать ли Forward Error Correction (если пакет потерян)
    decoded_data = decoder.decode(encoded_data, SAMPLES_PER_FRAME, decode_fec=False)
    print(f"Размер декодированных данных (PCM): {len(decoded_data)} байт")

    # --- Проверка (необязательно) ---
    if len(decoded_data) == len(pcm_data):
        print("\nРазмер исходных и декодированных PCM данных совпадает.")
        # Примечание: Из-за сжатия с потерями, сами байты могут немного отличаться.
        # if decoded_data == pcm_data:
        #     print("Содержимое исходных и декодированных данных идентично.")
        # else:
        #     print("Содержимое исходных и декодированных данных отличается (ожидаемо для lossy кодека).")
    else:
        print("\nОшибка: Размер исходных и декодированных PCM данных не совпадает!")

    # --- Дополнительные возможности (пример) ---
    # Установка битрейта (в битах в секунду)
    target_bitrate_bps = 64000
    encoder.bitrate = target_bitrate_bps
    print(f"\nУстановлен целевой битрейт кодера: {encoder.bitrate} бит/с")

    # Установка сложности кодирования (0-10, выше = лучше качество, больше CPU)
    encoder.complexity = 5
    print(f"Установлена сложность кодирования: {encoder.complexity}")

    # Включение VBR (Variable Bitrate)
    encoder.vbr = True
    print(f"Режим VBR: {'Включен' if encoder.vbr else 'Выключен'}")

except opuslib.OpusError as e:
    print(f"\nПроизошла ошибка Opus: {e}")
except ImportError:
    print("\nОшибка: Библиотека opuslib не найдена.")
    print("Установите ее: pip install opuslib")
    print("Также убедитесь, что установлена системная библиотека Opus:")
    print("  Debian/Ubuntu: sudo apt-get update && sudo apt-get install libopus-dev")
    print("  Fedora/CentOS: sudo yum install opus-devel")
    print("  macOS (Homebrew): brew install opus")
except Exception as e:
    print(f"\nПроизошла непредвиденная ошибка: {e}")

print("\nПример завершен.")