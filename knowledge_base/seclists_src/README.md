# SecLists Knowledge Base

Ini adalah subset dari kumpulan wordlist hacking populer (SecLists) untuk vulnerability testing dan penetration testing.

## Tentang
SecLists berisi wordlist terstruktur untuk berbagai tahap penetration testing:
- **Discovery**: Domain, IP, subdomain enumeration
- **Fuzzing**: Parameter, payload injection testing
- **Passwords**: Common dan rockyou kata sandi
- **Usernames**: Common usernames dan name lists
- **Web-Shells**: File shell testing (untuk analisis, bukan penggunaan langsung)
- **Wordlists**: Miscellaneous wordlists untuk berbagai tujuan

## Lisensi
MIT License (2019 Daniel Miessler)

## Struktur Direktori
Semua file berformat teks (.txt, .lst) berisi baris per baris entry untuk tools seperti:
- `ffuf`, `gobuster`, `wfuzz`
- `hydra`, `burpsuite`, `sqlmap`
- Custom wordlist generators
