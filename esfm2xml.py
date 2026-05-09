#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ESFM <-> XML Converter  -  Archivos de trofeos PS4
================================================================================
  Convierte archivos .ESFM (contenedor cifrado de trofeos PS4) a .XML legible
  y vuelve a cifrarlos de XML a ESFM.

  Formato ESFM:
    - Bytes 0x00-0x0F : IV de 16 bytes para AES-CBC-128
    - Bytes 0x10+     : Datos XML cifrados (con padding PKCS#7)

  Clave de cifrado:
    Se genera cifrando el NP Communication ID (ej. NPWR05506_00, rellenado con
    ceros hasta 16 bytes) usando AES-CBC-128 con la clave maestra Trophy_Key y
    un IV nulo.

  Uso:
    python esfm_converter.py esfm2xml  TROP.ESFM  NPWR05506_00  [salida.xml]
    python esfm_converter.py xml2esfm  entrada.xml NPWR05506_00  [salida.esfm]
    python esfm_converter.py auto      TROP.ESFM   NPWR05506_00  [carpeta/]

  Dependencias (solo stdlib + pycryptodome):
    pip install pycryptodome
================================================================================
"""

import sys
import os
import argparse
import struct
import re
import xml.dom.minidom as minidom
from pathlib import Path

# ---------------------------------------------------------------------------
# Importación de pycryptodome  (AES)
# ---------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print(
        "\n[ERROR] Falta la librería 'pycryptodome'.\n"
        "Instálala con:  pip install pycryptodome\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constantes del formato ESFM
# ---------------------------------------------------------------------------

# Clave maestra de trofeos PS4 (Trophy_Key) – conocida públicamente en psdevwiki
TROPHY_KEYGEN_KEY: bytes = bytes([
    0x21, 0xF4, 0x1A, 0x6B, 0xAD, 0x8A, 0x1D, 0x3E,
    0xCA, 0x7A, 0xD5, 0x86, 0xC1, 0x01, 0xB7, 0xA9,
])

# IV nulo para la derivación de clave
NULL_IV: bytes = b'\x00' * 16

IV_SIZE = 16   # Tamaño del IV incrustado en el ESFM
BLOCK_SIZE = 16


# ---------------------------------------------------------------------------
# Funciones criptográficas
# ---------------------------------------------------------------------------

def derive_key(np_comm_id: str) -> bytes:
    """
    Genera la clave AES a partir del NP Communication ID.

    El NP Comm ID (ej. "NPWR05506_00") se convierte a bytes ASCII,
    se rellena con ceros hasta 16 bytes y se cifra con TROPHY_KEYGEN_KEY
    usando AES-CBC (IV nulo). El resultado de 16 bytes es la clave.

    Args:
        np_comm_id: Identificador de comunicación NP, ej. "NPWR05506_00".

    Returns:
        Clave AES de 16 bytes.

    Raises:
        ValueError: Si el NP Comm ID es demasiado largo (>16 caracteres).
    """
    np_bytes = np_comm_id.encode("ascii")
    if len(np_bytes) > 16:
        raise ValueError(
            f"NP Communication ID demasiado largo: '{np_comm_id}' "
            f"({len(np_bytes)} bytes, máx. 16)."
        )
    # Rellenar con ceros hasta 16 bytes
    padded = np_bytes.ljust(16, b'\x00')

    cipher = AES.new(TROPHY_KEYGEN_KEY, AES.MODE_CBC, iv=NULL_IV)
    key = cipher.encrypt(padded)
    return key


def decrypt_esfm(esfm_data: bytes, key: bytes) -> bytes:
    """
    Descifra el contenido de un archivo ESFM.

    Estructura ESFM:
        [0x00 - 0x0F]  IV (16 bytes)
        [0x10 ...   ]  Datos cifrados con AES-CBC-128 + padding PKCS#7

    Args:
        esfm_data: Contenido binario completo del archivo .ESFM.
        key: Clave AES de 16 bytes derivada con `derive_key`.

    Returns:
        Bytes del XML descifrado (UTF-8).

    Raises:
        ValueError: Si el archivo es demasiado corto o el padding es inválido.
    """
    if len(esfm_data) < IV_SIZE + BLOCK_SIZE:
        raise ValueError(
            f"Archivo ESFM demasiado pequeño ({len(esfm_data)} bytes). "
            f"Mínimo esperado: {IV_SIZE + BLOCK_SIZE} bytes."
        )

    iv = esfm_data[:IV_SIZE]
    ciphertext = esfm_data[IV_SIZE:]

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"Longitud del bloque cifrado no es múltiplo de {BLOCK_SIZE}: "
            f"{len(ciphertext)} bytes."
        )

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext_padded = cipher.decrypt(ciphertext)

    try:
        plaintext = unpad(plaintext_padded, BLOCK_SIZE)
    except ValueError:
        # Algunos archivos usan padding con 0x0D en lugar de PKCS#7 estándar.
        # Intentar stripping manual de bytes nulos / 0x0D al final.
        plaintext = plaintext_padded.rstrip(b'\x00\x0d\x0a')

    return plaintext


def encrypt_esfm(xml_data: bytes, key: bytes, iv: bytes | None = None) -> bytes:
    """
    Cifra datos XML para generar un archivo ESFM.

    Args:
        xml_data: Contenido XML en bytes (se recomienda UTF-8).
        key: Clave AES de 16 bytes derivada con `derive_key`.
        iv: IV de 16 bytes. Si es None se generan bytes aleatorios seguros.

    Returns:
        Bytes del archivo .ESFM resultante (IV + datos cifrados).
    """
    if iv is None:
        # IV aleatorio criptográficamente seguro
        import os as _os
        iv = _os.urandom(IV_SIZE)

    if len(iv) != IV_SIZE:
        raise ValueError(f"El IV debe tener exactamente {IV_SIZE} bytes.")

    padded = pad(xml_data, BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(padded)

    return iv + ciphertext


# ---------------------------------------------------------------------------
# Funciones de manejo XML
# ---------------------------------------------------------------------------

def prettify_xml(raw_bytes: bytes) -> str:
    """
    Devuelve el XML formateado con indentación legible preservando UTF-8
    (tildes, acentos, eñes, caracteres CJK, etc.).

    Args:
        raw_bytes: Bytes del XML sin formatear.

    Returns:
        Cadena XML formateada como texto Unicode.
    """
    # Detectar encoding declarado en la cabecera <?xml ... encoding="..." ?>
    encoding = "utf-8"
    header_match = re.search(
        rb'<\?xml[^>]+encoding=["\']([^"\']+)["\']', raw_bytes[:200]
    )
    if header_match:
        encoding = header_match.group(1).decode("ascii", errors="replace").lower()

    # Decodificar con el encoding detectado
    try:
        xml_str = raw_bytes.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        xml_str = raw_bytes.decode("utf-8", errors="replace")

    # Eliminar la declaración XML existente para re-añadirla limpiamente
    xml_str_no_decl = re.sub(r'^<\?xml[^?]*\?>\s*', '', xml_str, count=1)

    try:
        dom = minidom.parseString(xml_str_no_decl.encode("utf-8"))
        pretty = dom.toprettyxml(indent="  ", encoding=None)
        # toprettyxml añade su propia declaración <?xml version="1.0" ?>
        # Reemplazarla por una con encoding explícito
        pretty = re.sub(
            r'^<\?xml[^?]*\?>',
            '<?xml version="1.0" encoding="UTF-8"?>',
            pretty,
            count=1
        )
        return pretty
    except Exception:
        # Si el XML no es parseable perfectamente, devolver tal cual
        return xml_str


def minify_xml(xml_text: str) -> bytes:
    """
    Convierte un XML formateado a bytes compactos listos para cifrar.
    Preserva el encoding UTF-8 (tildes, eñes, etc.).

    Args:
        xml_text: Texto XML (str).

    Returns:
        Bytes UTF-8 del XML compacto.
    """
    # Asegurarse de que la declaración tenga encoding="UTF-8"
    if not xml_text.strip().startswith("<?xml"):
        xml_text = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_text
    else:
        xml_text = re.sub(
            r'<\?xml[^?]*\?>',
            '<?xml version="1.0" encoding="UTF-8"?>',
            xml_text,
            count=1
        )
    return xml_text.encode("utf-8")


# ---------------------------------------------------------------------------
# Validación del NP Communication ID
# ---------------------------------------------------------------------------

NP_COMM_ID_PATTERN = re.compile(r'^NPWR\d{5}_\d{2}$', re.IGNORECASE)


def validate_np_comm_id(np_comm_id: str) -> str:
    """
    Valida y normaliza el NP Communication ID.

    Formato esperado: NPWR#####_## (ej. NPWR05506_00)

    Args:
        np_comm_id: Identificador a validar.

    Returns:
        ID en mayúsculas si es válido.

    Raises:
        ValueError: Si el formato no es correcto.
    """
    nid = np_comm_id.strip().upper()
    if not NP_COMM_ID_PATTERN.match(nid):
        raise ValueError(
            f"NP Communication ID inválido: '{np_comm_id}'.\n"
            "  Formato esperado: NPWRxxxxxnn  (ej. NPWR05506_00)"
        )
    return nid


# ---------------------------------------------------------------------------
# Operaciones principales
# ---------------------------------------------------------------------------

def esfm_to_xml(
    esfm_path: str | Path,
    np_comm_id: str,
    output_path: str | Path | None = None,
    pretty: bool = True,
) -> Path:
    """
    Convierte un archivo .ESFM a .XML.

    Args:
        esfm_path: Ruta al archivo .ESFM de entrada.
        np_comm_id: NP Communication ID del juego.
        output_path: Ruta del XML de salida. Si es None se genera
                     automáticamente junto al ESFM.
        pretty: Si True, el XML se formatea con indentación.

    Returns:
        Ruta del archivo XML generado.
    """
    esfm_path = Path(esfm_path)
    if not esfm_path.is_file():
        raise FileNotFoundError(f"Archivo no encontrado: {esfm_path}")

    np_comm_id = validate_np_comm_id(np_comm_id)
    key = derive_key(np_comm_id)

    print(f"[*] Leyendo  : {esfm_path}")
    esfm_data = esfm_path.read_bytes()
    print(f"[*] Tamaño   : {len(esfm_data):,} bytes")

    print(f"[*] NP ID    : {np_comm_id}")
    print(f"[*] Clave    : {key.hex()}")
    print(f"[*] IV       : {esfm_data[:IV_SIZE].hex()}")
    print(f"[*] Descifrando...")

    xml_bytes = decrypt_esfm(esfm_data, key)

    # Comprobar que el resultado parece XML
    xml_start = xml_bytes[:200].lstrip()
    if not (xml_start.startswith(b'<?xml') or xml_start.startswith(b'<')):
        print(
            "[AVISO] El resultado descifrado no parece XML. "
            "Verifica el NP Communication ID."
        )

    if pretty:
        xml_content = prettify_xml(xml_bytes)
    else:
        xml_content = xml_bytes.decode("utf-8", errors="replace")

    # Determinar ruta de salida
    if output_path is None:
        output_path = esfm_path.with_suffix(".xml")
    else:
        output_path = Path(output_path)
        if output_path.is_dir():
            output_path = output_path / esfm_path.with_suffix(".xml").name

    output_path.write_text(xml_content, encoding="utf-8")
    print(f"[✓] XML guardado en: {output_path}")
    print(f"    ({len(xml_content):,} caracteres, encoding UTF-8)")
    return output_path


def xml_to_esfm(
    xml_path: str | Path,
    np_comm_id: str,
    output_path: str | Path | None = None,
    iv: bytes | None = None,
) -> Path:
    """
    Convierte un archivo .XML a .ESFM cifrado.

    Args:
        xml_path: Ruta al archivo .XML de entrada.
        np_comm_id: NP Communication ID del juego.
        output_path: Ruta del ESFM de salida. Si es None se genera
                     automáticamente junto al XML.
        iv: IV de 16 bytes para el cifrado. Si None se genera aleatoriamente.

    Returns:
        Ruta del archivo ESFM generado.
    """
    xml_path = Path(xml_path)
    if not xml_path.is_file():
        raise FileNotFoundError(f"Archivo no encontrado: {xml_path}")

    np_comm_id = validate_np_comm_id(np_comm_id)
    key = derive_key(np_comm_id)

    print(f"[*] Leyendo  : {xml_path}")
    xml_text = xml_path.read_text(encoding="utf-8")
    xml_bytes = minify_xml(xml_text)
    print(f"[*] Tamaño XML: {len(xml_bytes):,} bytes")

    print(f"[*] NP ID    : {np_comm_id}")
    print(f"[*] Clave    : {key.hex()}")
    print(f"[*] Cifrando...")

    esfm_data = encrypt_esfm(xml_bytes, key, iv=iv)

    print(f"[*] IV usado : {esfm_data[:IV_SIZE].hex()}")

    # Determinar ruta de salida
    if output_path is None:
        output_path = xml_path.with_suffix(".esfm")
    else:
        output_path = Path(output_path)
        if output_path.is_dir():
            output_path = output_path / xml_path.with_suffix(".esfm").name

    output_path.write_bytes(esfm_data)
    print(f"[✓] ESFM guardado en: {output_path}")
    print(f"    ({len(esfm_data):,} bytes)")
    return output_path


def auto_convert(
    input_path: str | Path,
    np_comm_id: str,
    output_path: str | Path | None = None,
) -> Path:
    """
    Detecta automáticamente el tipo del archivo y aplica la conversión.

    - Si la extensión es .esfm  →  convierte a .xml
    - Si la extensión es .xml   →  convierte a .esfm
    - En caso contrario intenta leer el contenido para decidir.

    Args:
        input_path: Archivo de entrada (ESFM o XML).
        np_comm_id: NP Communication ID del juego.
        output_path: Destino opcional.

    Returns:
        Ruta del archivo de salida generado.
    """
    input_path = Path(input_path)
    ext = input_path.suffix.lower()

    if ext == ".esfm":
        return esfm_to_xml(input_path, np_comm_id, output_path)
    elif ext == ".xml":
        return xml_to_esfm(input_path, np_comm_id, output_path)
    else:
        # Intentar detectar por contenido
        try:
            snippet = input_path.read_bytes()[:16]
            # Si parece XML legible
            if snippet.lstrip()[:5] in (b'<?xml', b'<trop'):
                print(f"[*] Detectado como XML por contenido.")
                return xml_to_esfm(input_path, np_comm_id, output_path)
            else:
                print(f"[*] Detectado como ESFM por contenido.")
                return esfm_to_xml(input_path, np_comm_id, output_path)
        except Exception:
            raise ValueError(
                f"No se puede determinar el tipo de '{input_path}'. "
                "Usa el subcomando 'esfm2xml' o 'xml2esfm' explícitamente."
            )


# ---------------------------------------------------------------------------
# Interfaz de línea de comandos
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="esfm_converter",
        description=(
            "Conversor ESFM ↔ XML para archivos de trofeos de PS4.\n\n"
            "Ejemplos:\n"
            "  python esfm_converter.py esfm2xml TROP.ESFM NPWR05506_00\n"
            "  python esfm_converter.py xml2esfm TROP.xml  NPWR05506_00\n"
            "  python esfm_converter.py auto     TROP.ESFM NPWR05506_00 salida/\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- esfm2xml ----
    p_e2x = subparsers.add_parser(
        "esfm2xml",
        help="Descifra un .ESFM y lo guarda como .XML legible.",
    )
    p_e2x.add_argument("input",  help="Archivo .ESFM de entrada.")
    p_e2x.add_argument("npid",   help="NP Communication ID (ej. NPWR05506_00).")
    p_e2x.add_argument("output", nargs="?", default=None,
                        help="Archivo .XML de salida (opcional).")
    p_e2x.add_argument("--no-pretty", action="store_true",
                        help="No formatear el XML resultante.")

    # ---- xml2esfm ----
    p_x2e = subparsers.add_parser(
        "xml2esfm",
        help="Cifra un .XML y lo guarda como .ESFM.",
    )
    p_x2e.add_argument("input",  help="Archivo .XML de entrada.")
    p_x2e.add_argument("npid",   help="NP Communication ID (ej. NPWR05506_00).")
    p_x2e.add_argument("output", nargs="?", default=None,
                        help="Archivo .ESFM de salida (opcional).")
    p_x2e.add_argument("--iv",   default=None,
                        help="IV hex de 32 dígitos (16 bytes). Por defecto aleatorio.")

    # ---- auto ----
    p_auto = subparsers.add_parser(
        "auto",
        help="Detecta automáticamente el tipo y convierte.",
    )
    p_auto.add_argument("input",  help="Archivo de entrada (.ESFM o .XML).")
    p_auto.add_argument("npid",   help="NP Communication ID (ej. NPWR05506_00).")
    p_auto.add_argument("output", nargs="?", default=None,
                         help="Archivo o carpeta de salida (opcional).")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "esfm2xml":
            esfm_to_xml(
                args.input, args.npid, args.output,
                pretty=not args.no_pretty,
            )

        elif args.command == "xml2esfm":
            iv = None
            if args.iv:
                iv_hex = args.iv.replace(" ", "").replace(":", "")
                if len(iv_hex) != 32:
                    raise ValueError(
                        f"El IV debe tener 32 caracteres hex (16 bytes), "
                        f"se recibieron {len(iv_hex)}."
                    )
                iv = bytes.fromhex(iv_hex)
            xml_to_esfm(args.input, args.npid, args.output, iv=iv)

        elif args.command == "auto":
            auto_convert(args.input, args.npid, args.output)

    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Operación cancelada por el usuario.")
        return 130
    except Exception as e:
        print(f"\n[ERROR inesperado] {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    return 0


# ---------------------------------------------------------------------------
# API pública para uso como módulo
# ---------------------------------------------------------------------------

__all__ = [
    "derive_key",
    "decrypt_esfm",
    "encrypt_esfm",
    "esfm_to_xml",
    "xml_to_esfm",
    "auto_convert",
    "validate_np_comm_id",
    "prettify_xml",
    "minify_xml",
    "TROPHY_KEYGEN_KEY",
]

if __name__ == "__main__":
    sys.exit(main())
