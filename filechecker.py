import os
from pathlib import Path
magic_bytes = [

# (signature, offset, description)
    (b'MZ',                         0,   "Windows executable (.exe, .dll, .sys)"),
    (b'\x4d\x5a',                   0,   "Windows executable (alternative spelling)"),
    (b'\x7fELF',                    0,   "Linux/Mac executable (ELF)"),
    (b'\xca\xfe\xba\xbe',           0,   "Mach-O executable (macOS/iOS universal)"),
    (b'\xfe\xed\xfa\xce',           0,   "Mach-O executable (macOS 64-bit)"),
    (b'\xfe\xed\xfa\xcf',           0,   "Mach-O executable (iOS 64-bit)"),
    (b'\xff\xd8\xff',               0,   "JPEG image"),
    (b'\x89PNG\r\n\x1a\n',          0,   "PNG image"),
    (b'GIF87a',                     0,   "GIF image (1987a)"),
    (b'GIF89a',                     0,   "GIF image (1989a)"),
    (b'RIFF',                       0,   "RIFF container"),
    (b'WEBP',                       8,   "WebP image"),
    (b'BM',                         0,   "BMP image"),
    (b'II*\x00',                    0,   "TIFF image (little-endian)"),
    (b'MM\x00*',                    0,   "TIFF image (big-endian)"),
    (b'\x00\x00\x01\x00',           0,   "ICO icon file"),
    (b'\x00\x00\x02\x00',           0,   "CUR cursor file"),
    (b'8BPS',                       0,   "Photoshop PSD"),
    (b'%PDF',                       0,   "PDF document"),
    (b'PK\x03\x04',                 0,   "ZIP-based format (.zip, .docx, .xlsx, .pptx, .jar, .apk, .odt)"),
    (b'PK\x05\x06',                 0,   "Empty ZIP archive"),
    (b'PK\x07\x08',                 0,   "Spanned ZIP archive"),
    (b'Rar!\x1a\x07\x00',           0,   "RAR archive (v1.5-v4)"),
    (b'Rar!\x1a\x07\x01\x00',       0,   "RAR5 archive"),
    (b'7z\xbc\xaf\x27\x1c',         0,   "7-Zip archive"),
    (b'\x1f\x8b',                   0,   "GZIP archive"),
    (b'BZh',                        0,   "BZIP2 archive"),
    (b'\xfd7zXZ\x00',               0,   "XZ archive"),
    (b'ftyp',                       4,   "MP4 / QuickTime / M4A / M4V"),
    (b'moov',                       4,   "MP4 (alternative atom)"),
    (b'wide',                       8,   "MP4 (common filler)"),
    (b'free',                       8,   "MP4 free atom"),
    (b'OggS',                       0,   "OGG / OGV / OGA media"),
    (b'FLV\x01',                    0,   "FLV video"),
    (b'ID3',                        0,   "MP3 with ID3 tags"),
    (b'fLaC',                       0,   "FLAC audio"),
    (b'MThd',                       0,   "MIDI audio"),
    (b'\x1a\x45\xdf\xa3',           0,   "Matroska / WebM (.mkv, .webm)"),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, "Old MS Office (.doc, .xls, .ppt)"),
    (b'\xec\xa5\xc1\x00',           512, "New MS Office .docx/.xlsx with junk at start (rare phishing)"),
    (b'<!DOCTYPE HTML',             0,   "HTML file (case-insensitive, but we check first bytes)"),
    (b'<?xml',                      0,   "XML-based file"),
    (b'%!PS',                       0,   "PostScript file"),
    (b'\x00\x61\x73\x6d',           0,   "Android DEX (Dalvik Executable)"),
    (b'dex\n035',                   0,   "Android DEX (newer)"),
    (b'\xca\xfe\xba\xbe',           0,   "Java class file"),
    (b'PK\x00\x00',                 0,   "JAR with extra data (sometimes used in phishing)"),
    (b'WINRAR',                     0,   "Old RAR (very rare)"),
    (b'ITSF',                       0,   "CHM Help file (dangerous, often exploited)"),
    (b'\x50\x4b\x03\x04\x14\x00\x06\x00', 0, "DOCX with password (common phishing)"),



]

FILE = input("etner path of the file you want to check,pleease enter valid path:")

"""
 with this commented code we can read that exatly bytes from the file specifineg the lenght 512 of output which is more than enough you would
 cheeeck each file signature but this would take a lot of time so i genereatedthis magic_bytes with AI.
"""
# with open(FILE,'rb') as file:
#     first_bytes =file.read(512)

data = Path(FILE).read_bytes()[:512]
def file_type_check() :
    for signature, offset, name in magic_bytes:
        if len(data)> offset + len(signature):
            if data[offset:offset+len(signature)] == signature:
                if signature == b'ftyp' and len(data) > offset+16:
                    brand = data[offset+4:offset+8]
                    return f"MP4 video/audio-brand: {brand!r}"
                return f"Real type -> {name}"
                
    return "Unknown file type"

print(file_type_check())        
