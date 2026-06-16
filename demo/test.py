#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KAMUSM E-İmza Kartı Debug ve Test Aracı
Gerekli kütüphaneler: pip install PyKCS11 cryptography python-pkcs11
"""

import os
import sys
import ctypes
from ctypes import wintypes
import platform


def check_system_info():
    """Sistem bilgilerini kontrol et"""
    print("=== Sistem Bilgileri ===")
    print(f"Python versiyon: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Architecture: {platform.architecture()}")
    print(f"İşlemci: {platform.processor()}")
    print()


def check_dll_dependencies():
    """DLL bağımlılıklarını kontrol et"""
    print("=== DLL Bağımlılıkları Kontrolü ===")
    lib_path = os.path.join(os.path.dirname(__file__), "akis_lib", "akisp11.dll")

    if not os.path.exists(lib_path):
        print(f"HATA: {lib_path} bulunamadı!")
        return False

    print(f"DLL dosyası bulundu: {lib_path}")
    print(f"Dosya boyutu: {os.path.getsize(lib_path)} byte")

    try:
        # DLL'i doğrudan yükle
        dll = ctypes.windll.LoadLibrary(lib_path)
        print("✓ DLL başarıyla yüklendi (ctypes)")

        # PKCS#11 fonksiyonlarının varlığını kontrol et
        required_functions = [
            'C_Initialize', 'C_Finalize', 'C_GetInfo',
            'C_GetSlotList', 'C_GetTokenInfo', 'C_OpenSession'
        ]

        missing_functions = []
        for func_name in required_functions:
            try:
                getattr(dll, func_name)
                print(f"✓ {func_name} fonksiyonu mevcut")
            except AttributeError:
                missing_functions.append(func_name)
                print(f"✗ {func_name} fonksiyonu bulunamadı")

        if missing_functions:
            print(f"Eksik fonksiyonlar: {missing_functions}")
            return False

        return True

    except Exception as e:
        print(f"✗ DLL yükleme hatası: {e}")
        return False


def test_with_raw_ctypes():
    """Ham ctypes ile PKCS#11 test et"""
    print("\n=== Ham CTypes ile PKCS#11 Testi ===")
    lib_path = os.path.join(os.path.dirname(__file__), "akis_lib", "akisp11.dll")

    try:
        # DLL'i yükle
        pkcs11 = ctypes.windll.LoadLibrary(lib_path)

        # C_Initialize çağır
        print("C_Initialize çağrılıyor...")
        result = pkcs11.C_Initialize(None)
        print(f"C_Initi