SecureFolderEncryptor

Ein sicheres, rekursives Ordner-Verschlüsselungstool in Python – ideal für den Schutz sensibler Daten durch AES-Verschlüsselung, PBKDF2-Key-Derivation, HMAC-Integritätsprüfung und strukturgetreue Wiederherstellung.

Funktionen:

AES-256 im CBC-Modus zur starken symmetrischen Verschlüsselung

PBKDF2 mit Salt zur sicheren Schlüsselerzeugung aus Passwörtern

PKCS#7 Padding für Blockkompatibilität

HMAC (SHA-256) zur Integritätsprüfung gegen Manipulation

Serialisierung mit pickle, um komplette Ordnerstrukturen zu sichern

CLI-Unterstützung mit Argumentparser für einfache Nutzung

Abhängigkeiten:

Python 3.7 oder höher

pycryptodome

Installation mit:

pip install pycryptodome

Nutzung:

Ordner verschlüsseln:

python encryptor.py --encrypt --input <Ordnerpfad> --output <Zieldatei> --password <Passwort>

Beispiel:

python encryptor.py --encrypt --input geheim --output geheim.enc --password meinpasswort

Datei entschlüsseln:

python encryptor.py --decrypt --input <verschlüsselte Datei> --output <Zielordner> --password <Passwort>

Beispiel:

python encryptor.py --decrypt --input geheim.enc --output wiederhergestellt --password meinpasswort

Sicherheitshinweise:

Das Tool speichert keine Klartext-Daten. Stelle sicher, dass du dein Passwort nicht verlierst – es gibt keine Wiederherstellung.

Vermeide schwache Passwörter. Die Sicherheit hängt direkt von der Passwortstärke ab.

Der Einsatz von pickle kann bei modifizierten Dateien potenziell unsicher sein. Nutze das Tool nur mit vertrauenswürdigen Daten.

Lizenz:

MIT License – frei nutzbar, veränderbar und verbreitbar. Siehe LICENSE-Datei für Details.

Entwickelt von Nash – für alle, die ihre Daten selbstbestimmt schützen wollen.

