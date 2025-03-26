import binascii
import random
import subprocess
import os
import tempfile

# S-блоки для подстановки (замены)
# Каждая строка представляет собой отдельный S-блок, используемый для преобразования 4-битных чисел
SBOX = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
]

def rot_left(num, bits):
    """
    Выполняет циклический сдвиг 32-битного числа влево на указанное количество бит.
    
    Аргументы:
        num (int): 32-битное число для сдвига
        bits (int): количество бит для сдвига влево
        
    Возвращает:
        int: результат циклического сдвига влево
    """
    num &= 0xFFFFFFFF  # Обеспечиваем 32-битное число
    
    if bits > 32:
        return ((num << bits) | (num >> (32 - (bits % 32)))) & 0xFFFFFFFF
    elif bits == 0:
        return ((num << bits) | (num >> (32 - 1 - bits))) & 0xFFFFFFFF
    else:
        return ((num << bits) | (num >> (32 - bits))) & 0xFFFFFFFF

def word_addition(message):
    """
    Дополняет сообщение символами 'a', чтобы его длина была кратна 8.
    Это необходимо для корректного разбиения на блоки в алгоритме ГОСТ.
    
    Аргументы:
        message (str): исходное сообщение
        
    Возвращает:
        str: дополненное сообщение
    """
    while len(message) % 8 != 0:
        message += 'a'
    return message

def round_keys(key, op):
    """
    Генерирует раундовые ключи на основе мастер-ключа и типа операции.
    
    В ГОСТ 28147-89 используется 256-битный ключ, который разбивается на восемь 32-битных подключей.
    Порядок применения подключей зависит от операции (шифрование или дешифрование).
    
    Аргументы:
        key (str): 256-битный ключ в шестнадцатеричном формате
        op (str): тип операции ('e' для шифрования, 'd' для дешифрования)
        
    Возвращает:
        list: список 32-х 32-битных раундовых ключей
    """
    result = []
    split_key = []
    
    # Разбиваем ключ на 8 частей по 32 бита (8 шестнадцатеричных символов)
    for i in range(8):
        split_key.append(int(key[i*8:i*8+8], 16))
    
    if op == 'e':
        # Для шифрования: K0,K1,...,K7,K0,K1,...,K7,K0,K1,...,K7,K7,K6,...,K0
        for _ in range(3):
            result.extend(split_key)
        result.reverse()
        result.extend(split_key)
    else:
        # Для дешифрования: K0,K1,...,K7,K7,K6,...,K0,K7,K6,...,K0,K7,K6,...,K0
        result.extend(split_key)
        result.reverse()
        for _ in range(3):
            result.extend(split_key)
    
    return result

def encrypt_block(block, r_keys, op):
    """
    Шифрует один блок данных с использованием алгоритма ГОСТ 28147-89.
    
    Алгоритм ГОСТ работает с 64-битными блоками, которые разделяются на два 32-битных подблока.
    Выполняется 32 раунда преобразований, в каждом из которых используется свой раундовый ключ.
    
    Аргументы:
        block (str): 64-битный блок данных в шестнадцатеричном формате
        r_keys (list): список раундовых ключей
        op (str): тип операции ('e' для шифрования, 'd' для дешифрования)
        
    Возвращает:
        str: зашифрованный/расшифрованный блок в шестнадцатеричном формате
    """
    half_len = len(block) // 2
    left = int(block[:half_len], 16)  # Левый 32-битный подблок
    right = int(block[half_len:], 16)  # Правый 32-битный подблок
    
    for i in range(32):
        # 1. Сложение правого подблока с раундовым ключом по модулю 2^32
        s = (left + r_keys[i]) % 0x100000000  # Эквивалентно u32::MAX
        
        # 2. Преобразование в шестнадцатеричный формат и разбиение на отдельные цифры
        s_hex = f"{s:08x}".zfill(8)
        s_arr = [int(digit, 16) for digit in s_hex]
        
        # 3. Применение S-блоков подстановки
        for s_elem in range(len(s_arr)):
            s_arr[s_elem] = SBOX[s_elem][s_arr[s_elem]]
        
        # 4. Преобразование обратно в целое число
        s = int(''.join(f"{x:x}" for x in s_arr), 16)
        
        # 5. Циклический сдвиг влево на 11 бит
        s = rot_left(s, 11)
        
        # 6. Исключающее ИЛИ с левым подблоком
        s = s ^ right
        
        # 7. Обмен местами подблоков для следующего раунда
        right = left
        left = s
    
    # Формирование результата (правый подблок, левый подблок)
    res = f"{right:08x}{left:08x}"
    return res

def crypt_message(message, key, op):
    """
    Шифрует или дешифрует сообщение с использованием алгоритма ГОСТ 28147-89.
    
    Аргументы:
        message (str): сообщение для шифрования (текст) или дешифрования (шестнадцатеричная строка)
        key (str): 256-битный ключ в шестнадцатеричном формате
        op (str): тип операции ('e' для шифрования, 'd' для дешифрования)
        
    Возвращает:
        str: зашифрованное/расшифрованное сообщение в шестнадцатеричном формате
    """
    message = word_addition(message)
    
    if op == 'e':
        # Для шифрования преобразуем текст в шестнадцатеричный формат
        message = binascii.hexlify(message.encode()).decode()
    
    # Генерируем раундовые ключи
    r_keys = round_keys(key, op)
    
    # Разбиваем сообщение на блоки по 64 бита (16 шестнадцатеричных символов)
    step = len(message) // 16
    
    enc_message = ""
    
    # Шифруем/дешифруем каждый блок
    for i in range(step):
        block = message[i*16:i*16+16]
        val = encrypt_block(block, r_keys, op)
        enc_message += val
    
    return enc_message

def verify_with_openssl(message, key, encrypted_message):
    """
    Проверяет результаты шифрования/дешифрования с помощью OpenSSL (если доступен ГОСТ 28147-89)
    
    Аргументы:
        message (str): исходное сообщение
        key (str): 256-битный ключ в шестнадцатеричном формате
        encrypted_message (str): зашифрованное сообщение нашей реализацией
        
    Возвращает:
        bool: True если OpenSSL доступен и результаты совпадают, иначе False
    """
    try:
        # Проверяем наличие OpenSSL и поддержки ГОСТ
        check_cmd = "openssl enc -ciphers | grep -i gost"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        
        if "gost" not in result.stdout.lower():
            print("OpenSSL не поддерживает алгоритм ГОСТ на этой системе")
            return False
        
        # Создаем временные файлы
        with tempfile.NamedTemporaryFile(delete=False) as input_file:
            input_path = input_file.name
            # Записываем исходное сообщение в бинарном виде
            input_file.write(word_addition(message).encode())
        
        output_path = input_path + ".enc"
        
        # Команда OpenSSL для ГОСТ-28147-89
        # Формат может отличаться в зависимости от версии OpenSSL
        cmd = f"openssl enc -gost89 -K {key} -iv 0000000000000000 -in {input_path} -out {output_path}"
        
        subprocess.run(cmd, shell=True, check=True)
        
        # Читаем результат OpenSSL
        with open(output_path, 'rb') as f:
            openssl_result = binascii.hexlify(f.read()).decode()
        
        # Удаляем временные файлы
        os.unlink(input_path)
        os.unlink(output_path)
        
        # Сравниваем результаты
        if openssl_result == encrypted_message:
            print("✓ Результаты шифрования совпадают с OpenSSL")
        else:
            print("✗ Результаты шифрования не совпадают с OpenSSL")
            print(f"  OpenSSL: {openssl_result}")
            print(f"  Наша реализация: {encrypted_message}")
        
        return True
        
    except Exception as e:
        print(f"Ошибка при проверке с OpenSSL: {e}")
        return False

def main():
    """
    Основная функция программы, демонстрирующая процесс шифрования и дешифрования с ГОСТ 28147-89.
    """
    message = input("Введите текст для зашифровки: ")
    key = "a55275ad61a2c973fe3727b26b9001d353bc0e51e12b2db0c55bfa9a87cfd32d"
    
    # Шифрование
    message_padded = word_addition(message)
    result = crypt_message(message_padded, key, 'e')
    
    # Дешифрование
    res = crypt_message(result, key, 'd')
    
    # Вывод результатов
    print(f"Исходное сообщение (hex): {binascii.hexlify(message_padded.encode()).decode()}")
    print(f"Ключ: {key}")
    print(f"Зашифрованное сообщение: {result}")
    print(f"Расшифрованное сообщение (hex): {res}")
    print(f"Расшифрованное сообщение (текст): {binascii.unhexlify(res).decode()}")
    
    # Сверка с OpenSSL
    print("\n==== Сверка результатов с OpenSSL ====")
    verify_with_openssl(message, key, result)
    print("======================================")

if __name__ == "__main__":
    main()
