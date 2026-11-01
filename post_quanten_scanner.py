#!/usr/bin/env python3
"""Post-Quanten-Code-Scanner als einzelne Python-Datei.

Python 3.10+; nur Standardbibliothek. pyproject.toml erfordert Python 3.11+.
Keine weiteren Skriptdateien erforderlich. Keine Installation/Projekt-Codeausfuehrung.

Beispiel:
    python post_quanten_scanner.py PROJEKTORDNER --json bericht.json --html bericht.html

Python: ausgewaehlte Bibliotheksaufrufe ueber Syntaxbaum-Analyse.
Java, JavaScript und TypeScript: ausgewaehlte API-Heuristik und Textmuster.
PHP und weitere unterstuetzte Sprachen: begrenzte Textheuristik.
Ausgewaehlte lokale Abhaengigkeitsdateien: begrenztes Bibliotheksinventar.
Versionierte BSI-Quellenhinweise und lokaler Bibliothekskatalog; keine Live-Abfrage,
CVE-Analyse oder vollstaendige Sicherheits-/Konformitaetspruefung.
"""
from __future__ import annotations
from types import SimpleNamespace as _SimpleNamespace

import copy as _bsi_copy
import html as _bsi_html
import re as _bsi_re
_bsi_RISK_LABELS = {'unknown': 'Noch nicht bewertet', 'high': 'Hoch (selbst angegeben)', 'medium': 'Mittel (selbst angegeben)', 'low': 'Niedrig (selbst angegeben)'}
_bsi_PROTOCOL_LABELS = {'general': 'Allgemein', 'tls': 'TLS', 'ipsec': 'IPsec / IKEv2', 'ssh': 'SSH'}
_bsi_SOURCES = [{'id': 'bsi-roadmap-2026', 'title': 'Nationale Umsetzung der EU-Roadmap zur Umstellung auf Post-Quanten-Kryptografie', 'date': '2026-09-11', 'scope': 'Gemeinsame Leitlinie von BMDS, BMI und BSI; bereitgestellte lokale Fassung, Seiten 5–8', 'filename': 'Leitlinie-Umstellung-PQC.pdf', 'sha256': 'ad714afe5fc46d1b488a022b232c0c9c1e2f93cd3dcd70c268c89e0287ce19dc', 'url': 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Krypto/Leitlinie-Umstellung-PQC.pdf?__blob=publicationFile&v=3'}, {'id': 'bsi-basics-2021', 'title': 'Kryptografie quantensicher gestalten', 'date': '2021-10', 'scope': 'Grundlagen und Vorbereitung, insbesondere Abschnitte 6.1, 6.2, 6.5 und 6.11–6.12; keine aktuelle Algorithmenfreigabeliste', 'filename': 'Kryptografie-quantensicher-gestalten.pdf', 'sha256': 'ccdccd210628287d446684433d9819b0305f0ed906bf204c69ef12ffa72963a3', 'url': 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/Broschueren/Kryptografie-quantensicher-gestalten.pdf'}]
_bsi_SOURCES += [{'id': 'bsi-tr02102-1-2026', 'title': 'BSI TR-02102-1: Kryptographische Verfahren – Empfehlungen und Schlüssellängen', 'date': '2026-01-23', 'version': '2026-01', 'filename': 'BSI-TR-02102.pdf', 'scope': 'Ausgewählte Abschnitte: 2.1–2.4 und 5.3.4; insbesondere S. 30–31, 41 und 59–60', 'sha256': '07d18200c1434887ee31c503e633861d4dddb3c13d5881f533eac75f3720dcec', 'url': 'https://www.bsi.bund.de/TR-02102'}, {'id': 'bsi-tr02102-2-2026', 'title': 'BSI TR-02102-2: Verwendung von TLS', 'date': '2026-01-27', 'version': '2026-01', 'filename': 'BSI-TR-02102-2.pdf', 'scope': 'Abschnitte 3.1–3.2 und 3.4; insbesondere S. 6 und 12–14', 'sha256': 'eed80d1a38ec0d7d8908765c3a09ea6f17a7ca729bef95b0d358d5d129af3f1f', 'url': 'https://www.bsi.bund.de/TR-02102'}, {'id': 'bsi-tr02102-3-2026', 'title': 'BSI TR-02102-3: Verwendung von IPsec und IKEv2', 'date': '2026-01-27', 'version': '2026-01', 'filename': 'BSI-TR-02102-3.pdf', 'scope': 'Abschnitte 3.1 und 3.2.4; insbesondere S. 9 und 11', 'sha256': '63f573df66cfbb04e9d233a111900989677f46aa3de67fa0ccacd3329d75dd48', 'url': 'https://www.bsi.bund.de/TR-02102'}, {'id': 'bsi-tr02102-4-2026', 'title': 'BSI TR-02102-4: Verwendung von SSH', 'date': '2026-01-27', 'version': '2026-01', 'filename': 'BSI-TR-02102-4.pdf', 'scope': 'Abschnitte 3.1–3.3; insbesondere S. 7–8', 'sha256': 'd1ae824d84b8028b3e780c046b29aaaa48a2421be352cf4d3c36c7682eac9750', 'url': 'https://www.bsi.bund.de/TR-02102'}, {'id': 'bsi-mceliece-2026-09-29', 'title': 'Hinweise zu aktuellen Entwicklungen um Classic McEliece', 'date': '2026-09-29', 'filename': 'Hinweis_Classic_McEliece.pdf', 'scope': 'S. 1–3; neuerer Einsatzhinweis zu Classic McEliece', 'sha256': '91080d26a4d0a04ce44f9ebf2bb7e07b705e91976933da31bb2004ad086d38b9', 'url': 'https://www.bsi.bund.de/TR-02102'}]
_bsi_MCELIECE_ADVISORY = 'BSI-MCELIECE-2026-09-29'
_bsi_MCELIECE_TEXT = 'BSI-Hinweis vom 29.09.2026, S. 1–3: Classic McEliece soll derzeit nicht mehr in Neuentwicklungen und bei der Planung neuer kryptographischer Anwendungen verwendet werden. Bestehenden Einsatz und Hybridkombination gesondert prüfen. Das Dokument beschreibt noch keinen praktischen Angriff auf die in TR-02102-1 empfohlenen Parametersätze; es bewertet nicht alle Installationen als gebrochen. Dieser neuere Einsatzhinweis hat hier Vorrang vor der älteren positiven Einordnung in der TR-Fassung Januar 2026.'
_bsi_PROTOCOL_NOTES = {'general': [{'source': 'bsi-tr02102-1-2026', 'pages': '30–31', 'text': 'Alleinige klassische Schlüsseleinigung: Empfehlung bis Ende 2031, bei sehr hohem Schutzbedarf Umstellung bereits bis Ende 2030. Diese Einsatzrolle wird nicht allein aus einem RSA-/ECC-Namen bestimmt.'}, {'source': 'bsi-tr02102-1-2026', 'pages': '31', 'text': 'Klassische Signaturen: Umstellung bis spätestens 2035; die Fassung formuliert die Einsatzempfehlung bis Ende 2035 ausdrücklich als voraussichtlich. Kürzere verfahrensspezifische Zeiträume bleiben zu beachten.'}], 'tls': [{'source': 'bsi-tr02102-2-2026', 'pages': '6', 'text': 'TLS 1.3 bevorzugen; TLS 1.2 wird in der Fassung 2026-01 nur bis Ende 2031 empfohlen. Eine Protokollversionsangabe allein belegt keine quantensichere Schlüsseleinigung.'}, {'source': 'bsi-tr02102-2-2026', 'pages': '12–14', 'text': 'TLS-1.3-Cipher-Suiten legen AEAD und Hash fest, nicht die Schlüsselaustauschgruppe. Gruppen, Signaturen und Zertifikate getrennt prüfen. Die Empfehlung bestimmter PQC-Hybridgruppen wird in dieser Fassung erst nach Verabschiedung des zugehörigen RFC beabsichtigt; späteren Stand prüfen.'}], 'ipsec': [{'source': 'bsi-tr02102-3-2026', 'pages': '9, 11', 'text': 'IKEv2: Klassische DH-Gruppen allein nur bis Ende 2031 empfohlen. Die Fassung unterscheidet alleinige und hybride Nutzung; die Empfehlung von ML-KEM-768/1024 in IKEv2 ist an die Verabschiedung des referenzierten RFC geknüpft. Einen Algorithmusnamen nicht als vollständige IKE-/ESP-Konformität behandeln.'}], 'ssh': [{'source': 'bsi-tr02102-4-2026', 'pages': '7–8', 'text': 'SSH-2 wird empfohlen, SSH-1 nicht. Schlüsseleinigung, Server-/Benutzerauthentisierung und symmetrische Verschlüsselung getrennt bewerten; alleinige klassische KEX-Nutzung nur bis Ende 2031 empfohlen. Die genannten PQC-Hybrid-KEX-Verfahren sind in dieser Fassung noch an den referenzierten RFC geknüpft.'}]}
_bsi_LIMIT = 'BSI-Orientierung zur manuellen Prüfung. Risikostufe, Einsatzrolle, Hybridkombination, konkrete Parameter und rechtliche Verbindlichkeit werden nicht aus dem Quellcode abgeleitet. Dies ist weder eine TR-02102-Konformitätsprüfung noch eine BSI-Freigabe.'
_bsi_CHECKLIST = ['Verantwortliche, Anwendung, Geschäftsprozess, Protokolle und Kryptografie-Abhängigkeiten erfassen.', 'Vertraulichkeitsdauer, möglichen Schaden und voraussichtliche Umstellungsdauer bewerten; daraus das Anwendungsrisiko ableiten.', 'Schlüsseleinigung, Signaturen und Datenverschlüsselung getrennt betrachten; eine sichere Hybridintegration im jeweiligen Protokoll prüfen.', 'Aktuelle TR-02102 einschließlich Parameter, Einsatzbedingungen und bereichsspezifischer Anforderungen prüfen.', 'Lieferanten, Kommunikationspartner, PKI und Updatepfade einbeziehen; Interoperabilität testen und das Inventar aktuell halten.']
_bsi_MILESTONES = [{'date': '2026-12-31', 'meaning': 'Initiales Inventar sowie Vorbereitungs- und Umsetzungsplanung abschließen; erste Umstellungsschritte beginnen.', 'source': 'bsi-roadmap-2026', 'pages': '5–7'}, {'date': '2030-12-31', 'meaning': 'Empfohlener Abschluss für Anwendungsfälle mit hohem Risiko.', 'source': 'bsi-roadmap-2026', 'pages': '5–6'}, {'date': '2035-12-31', 'meaning': 'Empfohlener Abschluss für mittleres Risiko; bei niedrigem Risiko so weit wie möglich abgeschlossen.', 'source': 'bsi-roadmap-2026', 'pages': '5'}]

def _bsi_profile(risk_context='unknown', protocol_context='general'):
    if risk_context not in _bsi_RISK_LABELS:
        raise ValueError('Unbekannte manuelle Risikoeinstufung.')
    if protocol_context not in _bsi_PROTOCOL_LABELS:
        raise ValueError('Unbekannter manuell gewählter Protokollkontext.')
    target = {'high': '2030-12-31', 'medium': '2035-12-31', 'low': '2035-12-31'}.get(risk_context)
    return {'name': 'BSI-Orientierung', 'profile_version': '2026-10-23-tr2026-01-mce2026-09-29', 'reviewed_on': '2026-10-23', 'status': 'manual_review_only', 'compliance': 'not_assessed', 'limit': _bsi_LIMIT, 'risk_context': {'level': risk_context, 'label': _bsi_RISK_LABELS[risk_context], 'origin': 'not_assessed' if risk_context == 'unknown' else 'user_declared', 'recommended_target': target, 'target_qualification': 'so weit wie möglich' if risk_context == 'low' else 'Empfehlung; konkrete Anwendbarkeit prüfen'}, 'milestones': _bsi_copy.deepcopy(_bsi_MILESTONES), 'checklist': list(_bsi_CHECKLIST), 'sources': _bsi_copy.deepcopy(_bsi_SOURCES), 'protocol_context': {'value': protocol_context, 'label': _bsi_PROTOCOL_LABELS[protocol_context], 'origin': 'user_selected'}, 'protocol_notes': _bsi_copy.deepcopy(_bsi_PROTOCOL_NOTES['general'] + ([] if protocol_context == 'general' else _bsi_PROTOCOL_NOTES[protocol_context])), 'advisory_catalog': [{'id': _bsi_MCELIECE_ADVISORY, 'source': 'bsi-mceliece-2026-09-29', 'text': _bsi_MCELIECE_TEXT}], 'qkd_note': 'Quantenbasierte Schlüsselverteilung (QKD) ist ein anderes technisches Verfahren als softwarebasierte PQC. Der Scanner untersucht keine QKD-Hardware oder deren Sicherheit.', 'source_note': 'Ausgewählte Abschnitte der bereitgestellten TR-02102-Teile 1–4 (2026-01) und der neuere McEliece-Hinweis (29.09.2026) wurden lokal geprüft. Kein vollständiger Richtliniencheck und keine Live-Aktualitätsprüfung. Online gesperrte BSI-Seiten werden nicht als gelesen ausgegeben.'}

def _bsi_finding_note(algorithm, category):
    if algorithm == 'Classic McEliece':
        return _bsi_MCELIECE_TEXT
    if algorithm == 'XMSS/LMS':
        return 'Zustandsbehaftete Signaturen: Zustandsverwaltung und Ausschluss der Wiederverwendung verbrauchten Schlüsselmaterials prüfen. Eine Namensfundstelle belegt diese Eigenschaften nicht (TR-02102-1, Fassung 2026-01, Abschnitt 5.3.4.3, S. 60).'
    if category == 'migration_review':
        return 'Einsatzrolle, Schutzdauer und Anwendungsrisiko erfassen. Eine einzelne klassische API-Fundstelle belegt weder die alleinige Verwendung noch das Fehlen einer PQC-Hybridlösung (Leitlinie 2026, Abschnitte 4.3–4.5).'
    if category in {'pqc_reference', 'legacy_pqc_reference'}:
        return 'Aktuelle Variante, Parameter und sichere Protokoll-/Hybridintegration prüfen. Auch zwei gemeinsam gefundene Algorithmusnamen beweisen keine Hybridkombination (Leitlinie 2026, Abschnitt 4.4).'
    return 'Den kryptografischen Verwendungszweck und die Parameter im Gesamtverfahren prüfen. Aus diesem Inventarhinweis allein folgt keine PQC-Risikostufe oder Konformitätsaussage.'

def _bsi_recognized_variant(value, algorithm):
    """Extract only recognized names, never copy arbitrary string literals into reports."""
    patterns = {'ML-KEM': ('ml[-_]?kem[-_]?(512|768|1024)(?![A-Za-z0-9_])', 'ML-KEM-'), 'ML-DSA': ('ml[-_]?dsa[-_]?(44|65|87)(?![A-Za-z0-9_])', 'ML-DSA-'), 'FrodoKEM': ('frodokem[-_]?(640|976|1344)(?=$|[^A-Za-z0-9_]|[-_](?:aes|shake))', 'FrodoKEM-')}
    if algorithm in patterns:
        pattern, prefix = patterns[algorithm]
        match = _bsi_re.match(pattern, value, _bsi_re.I)
        return prefix + match.group(1) if match else None
    if algorithm == 'SLH-DSA':
        match = _bsi_re.match('slh[-_]?dsa[-_](sha2|shake)[-_](128|192|256)(s|f)(?![A-Za-z0-9_])', value, _bsi_re.I)
        if match:
            return 'SLH-DSA-' + match.group(1).upper() + '-' + match.group(2) + match.group(3).lower()
    return None

def _bsi_parameter_review(algorithm, variant):
    if algorithm == 'Classic McEliece':
        return {'status': 'special_advisory', 'source': 'bsi-mceliece-2026-09-29', 'text': _bsi_MCELIECE_TEXT}
    tables = {'ML-KEM': ('2.7', {'ML-KEM-768', 'ML-KEM-1024'}), 'ML-DSA': ('5.7', {'ML-DSA-65', 'ML-DSA-87'}), 'FrodoKEM': ('2.5', {'FrodoKEM-976', 'FrodoKEM-1344'}), 'SLH-DSA': ('5.6', {f'SLH-DSA-{h}-{n}{s}' for h in ('SHA2', 'SHAKE') for n in (192, 256) for s in ('s', 'f')})}
    if algorithm not in tables or variant is None:
        return {'status': 'not_assessed', 'source': None, 'text': 'Parameter nicht ausreichend erkannt; keine Aussage zur TR-Parameterliste.'}
    table, listed = tables[algorithm]
    if variant not in listed:
        return {'status': 'not_listed_in_reviewed_table', 'source': 'bsi-tr02102-1-2026', 'text': f'{variant} ist nicht in Tabelle {table} der bereitgestellten TR-02102-1, Fassung 2026-01, aufgeführt. Das ist ein Prüfhinweis und kein Beleg für einen praktischen Angriff.'}
    conditions = ' Bei ML-DSA/SLH-DSA sind insbesondere die hedged-Variante und weitere Einsatzbedingungen zu prüfen.' if algorithm in {'ML-DSA', 'SLH-DSA'} else ' Sichere Hybridisierung und weitere Einsatzbedingungen bleiben zu prüfen.'
    return {'status': 'listed_conditions_unchecked', 'source': 'bsi-tr02102-1-2026', 'text': f'{variant} ist in Tabelle {table} der bereitgestellten TR-02102-1, Fassung 2026-01, genannt; eine Namensübereinstimmung belegt keine konforme Implementierung.' + conditions}

def _bsi_as_text(data):
    risk = data['risk_context']
    lines = [data['limit'], 'Anwendungsrisiko: ' + risk['label']]
    if risk['recommended_target']:
        lines.append('Planungsziel laut Leitlinie: ' + risk['recommended_target'] + ' · ' + risk['target_qualification'])
    else:
        lines.append('Kein individuelles Planungsziel abgeleitet; das Anwendungsrisiko ist noch offen.')
    lines.extend((item['date'] + ': ' + item['meaning'] for item in data['milestones']))
    lines.extend(data['checklist'])
    lines.append('Manuell gewählter Protokollkontext: ' + data['protocol_context']['label'])
    lines.extend((item['text'] + ' (' + item['source'] + ', S. ' + item['pages'] + ')' for item in data['protocol_notes']))
    lines.extend((item['id'] + ': ' + item['text'] for item in data['advisory_catalog']))
    lines.extend([data['qkd_note'], data['source_note']])
    lines.extend((source['title'] + ' · ' + source['date'] + ' · ' + source['scope'] + '\n' + source['url'] for source in data['sources']))
    return '\n\n'.join(lines)

def _bsi_render_html(data):
    esc = lambda value: _bsi_html.escape(str(value), quote=True)
    risk = data['risk_context']
    target = ' · Planungsziel: ' + risk['recommended_target'] + ' (' + risk['target_qualification'] + ')' if risk['recommended_target'] else ' · Individuelles Planungsziel offen'
    rows = ''.join(('<li>' + esc(item['date'] + ': ' + item['meaning']) + '</li>' for item in data['milestones']))
    sources = ''.join(("<li><a href='" + esc(item['url']) + "'>" + esc(item['title']) + '</a> · ' + esc(item['date']) + '</li>' for item in data['sources']))
    notes = ''.join(('<li>' + esc(item['text'] + ' (' + item['source'] + ', S. ' + item['pages'] + ')') + '</li>' for item in data['protocol_notes']))
    return '<details><summary>BSI-Orientierung und Quellen</summary><p>' + esc(data['limit']) + '</p><p>' + esc('Anwendungsrisiko: ' + risk['label'] + target) + '</p><ul>' + rows + '</ul><p>Protokollkontext (manuell): ' + esc(data['protocol_context']['label']) + '</p><ul>' + notes + '</ul><ul>' + sources + '</ul><p>' + esc(data['source_note']) + '</p></details>'

bsi_profile = _SimpleNamespace(
    CHECKLIST=_bsi_CHECKLIST,
    LIMIT=_bsi_LIMIT,
    MCELIECE_ADVISORY=_bsi_MCELIECE_ADVISORY,
    MCELIECE_TEXT=_bsi_MCELIECE_TEXT,
    MILESTONES=_bsi_MILESTONES,
    PROTOCOL_LABELS=_bsi_PROTOCOL_LABELS,
    PROTOCOL_NOTES=_bsi_PROTOCOL_NOTES,
    RISK_LABELS=_bsi_RISK_LABELS,
    SOURCES=_bsi_SOURCES,
    as_text=_bsi_as_text,
    finding_note=_bsi_finding_note,
    parameter_review=_bsi_parameter_review,
    profile=_bsi_profile,
    recognized_variant=_bsi_recognized_variant,
    render_html=_bsi_render_html,
)

import json as _deps_json
import re as _deps_re
import xml.etree.ElementTree as _deps_ET
_deps_CATALOG_VERSION = '2026-10-31'
_deps_CATALOG = {'pypi': {'cryptography', 'pycryptodome', 'pycryptodomex', 'pynacl', 'pyopenssl', 'rsa', 'ecdsa', 'pyjwt', 'python-jose', 'pqcrypto', 'liboqs-python'}, 'npm': {'crypto-js', 'node-forge', 'tweetnacl', 'libsodium-wrappers', 'libsodium-wrappers-sumo', 'jsonwebtoken', 'jose', '@noble/ciphers', '@noble/curves', '@noble/hashes', '@noble/post-quantum', '@peculiar/webcrypto', 'crypto-browserify'}, 'maven': {'org.bouncycastle:' + artifact for artifact in ('bcprov-jdk18on', 'bcprov-jdk15on', 'bcprov-jdk15to18', 'bcpkix-jdk18on', 'bcpkix-jdk15on', 'bcpkix-jdk15to18', 'bctls-jdk18on', 'bctls-jdk15on', 'bcutil-jdk18on', 'bcutil-jdk15on')} | {'com.nimbusds:nimbus-jose-jwt', 'com.auth0:java-jwt', 'io.jsonwebtoken:jjwt', 'io.jsonwebtoken:jjwt-api', 'io.jsonwebtoken:jjwt-impl', 'io.jsonwebtoken:jjwt-jackson', 'org.conscrypt:conscrypt-openjdk-uber', 'org.conscrypt:conscrypt-android', 'net.i2p.crypto:eddsa'}}
_deps_ECOSYSTEM_LABELS = {'pypi': 'Python/PyPI', 'npm': 'JavaScript/npm', 'maven': 'Java/Maven'}
_deps_SCOPE_LABELS = {'runtime': 'Laufzeit', 'development': 'Entwicklung/Test', 'optional': 'Optional', 'peer': 'Peer-Abhängigkeit', 'build': 'Build', 'provided': 'Vom Laufzeitumfeld bereitgestellt', 'managed': 'Versionsverwaltung', 'conditional': 'Bedingt', 'constraint': 'Versionsvorgabe', 'unknown': 'Offen'}
_deps_SOURCE_LABELS = {'manifest': 'Projektdeklaration', 'lockfile': 'Lockfile-Verweis'}
_deps_KINDS = {'package.json': ('npm_package', 'npm'), 'package-lock.json': ('npm_lock', 'npm'), 'pyproject.toml': ('pyproject', 'pypi'), 'Pipfile.lock': ('pipfile_lock', 'pypi'), 'pom.xml': ('maven', 'maven')}
_deps_DEPENDENCY_NOTE = 'Kryptografie-Bibliothek in einer Projekt-/Abhängigkeitsdatei. Kein Nachweis installierter Pakete, tatsächlicher Nutzung, bestimmter Algorithmen oder einer Schwachstelle.'
_deps_DEPENDENCY_GUIDANCE = 'Eintrag mit dem Quellcode und dem tatsächlich ausgelieferten Build abgleichen. Eingesetzte Algorithmen, Version und Protokollintegration separat prüfen. Kein CVE- oder Versionssicherheitscheck.'
_deps_FIELDS = {'ecosystem', 'name', 'version', 'scope', 'source', 'alias', 'location_precision'}
_deps_MAX_DEPTH = 64
_deps_MAX_JSON_ITEMS = 100000

class _deps_Unavailable(ValueError):
    """A recognized format needs a standard-library feature unavailable in this runtime."""

def _deps_manifest_kind(path):
    name = str(path).replace('\\', '/').rsplit('/', 1)[-1]
    if name in _deps_KINDS:
        return _deps_KINDS[name]
    if _deps_re.fullmatch('(?:requirements|constraints)(?:[-_.][A-Za-z0-9_.-]+)?\\.(?:txt|in)', name):
        return ('requirements', 'pypi')
    return None

def _deps_safe_version(value):
    if not isinstance(value, str) or not 0 < len(value) <= 120:
        return None
    value = ' '.join(value.split())
    if not _deps_re.fullmatch('[0-9.*xX<>=!~^,\\[\\]() -]+', value) or not _deps_re.search('[0-9*]', value):
        return None
    return value

def _deps_normalize_name(ecosystem, name):
    if not isinstance(name, str):
        return None
    if ecosystem == 'pypi':
        name = _deps_re.sub('[-_.]+', '-', name).lower()
    return name if name in _deps_CATALOG[ecosystem] else None

def _deps_validate_dependency(value):
    if not isinstance(value, dict) or set(value) != _deps_FIELDS:
        raise ValueError('Ungültige Bibliotheksmetadaten.')
    ecosystem = value['ecosystem']
    if not isinstance(ecosystem, str) or ecosystem not in _deps_CATALOG:
        raise ValueError('Unbekanntes Bibliotheksökosystem.')
    if not isinstance(value['name'], str) or value['name'] not in _deps_CATALOG[ecosystem]:
        raise ValueError('Bibliotheksname liegt außerhalb des lokalen Katalogs.')
    for field, allowed in (('scope', _deps_SCOPE_LABELS), ('source', _deps_SOURCE_LABELS), ('location_precision', {'line', 'file'})):
        if not isinstance(value[field], str) or value[field] not in allowed:
            raise ValueError('Ungültige Einordnung einer Bibliothek.')
    if type(value['alias']) is not bool or (value['version'] is not None and _deps_safe_version(value['version']) != value['version']):
        raise ValueError('Ungültige Versions-/Aliasangabe einer Bibliothek.')
    return dict(value)

def _deps_describe(value):
    parts = ['Bibliothek: ' + value['name'], 'Ökosystem: ' + _deps_ECOSYSTEM_LABELS[value['ecosystem']], 'Version/Anforderung: ' + (value['version'] or 'nicht erfasst'), 'Bereich: ' + _deps_SCOPE_LABELS[value['scope']], 'Quelle: ' + _deps_SOURCE_LABELS[value['source']]]
    if value['alias']:
        parts.append('Über Paketalias deklariert')
    if value['location_precision'] == 'file':
        parts.append('Position gilt für die gesamte Datei')
    return ' · '.join(parts)

def _deps_json_with_positions(source):
    """Strict bounded JSON parser retaining field positions; errors never echo source values."""
    decoder = _deps_json.JSONDecoder(parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nicht standardkonstantes JSON.')))
    positions, count = ({}, 0)

    def space(i):
        while i < len(source) and source[i] in ' \t\r\n':
            i += 1
        return i

    def read(i, path, depth):
        nonlocal count
        count += 1
        if depth > _deps_MAX_DEPTH or count > _deps_MAX_JSON_ITEMS:
            raise ValueError('JSON-Struktur überschreitet das Analyselimit.')
        i = space(i)
        if i >= len(source):
            raise ValueError('Unvollständiges JSON.')
        if source[i] == '{':
            result, i = ({}, space(i + 1))
            if i < len(source) and source[i] == '}':
                return (result, i + 1)
            while True:
                start = i
                if i >= len(source) or source[i] != '"':
                    raise ValueError('Ungültiges JSON-Objekt.')
                key, i = decoder.raw_decode(source, i)
                if key in result:
                    raise ValueError('Doppelte JSON-Schlüssel sind nicht eindeutig.')
                i = space(i)
                if i >= len(source) or source[i] != ':':
                    raise ValueError('Ungültiges JSON-Objekt.')
                positions[path + (key,)] = start
                result[key], i = read(i + 1, path + (key,), depth + 1)
                i = space(i)
                if i < len(source) and source[i] == '}':
                    return (result, i + 1)
                if i >= len(source) or source[i] != ',':
                    raise ValueError('Ungültiges JSON-Objekt.')
                i = space(i + 1)
        if source[i] == '[':
            result, i = ([], space(i + 1))
            if i < len(source) and source[i] == ']':
                return (result, i + 1)
            while True:
                item, i = read(i, path + (len(result),), depth + 1)
                result.append(item)
                i = space(i)
                if i < len(source) and source[i] == ']':
                    return (result, i + 1)
                if i >= len(source) or source[i] != ',':
                    raise ValueError('Ungültiges JSON-Array.')
                i = space(i + 1)
        return decoder.raw_decode(source, i)
    try:
        result, end = read(0, (), 0)
        if space(end) != len(source) or not isinstance(result, dict):
            raise ValueError('JSON-Manifest benötigt genau ein Wurzelobjekt.')
        return (result, positions)
    except _deps_json.JSONDecodeError:
        raise ValueError('Ungültige JSON-Syntax im Manifest.') from None

def _deps_parse_manifest(path, source):
    descriptor = _deps_manifest_kind(path)
    if descriptor is None:
        raise ValueError('Unbekanntes Manifestformat.')
    kind, ecosystem = descriptor
    records, warnings = ([], [])
    positions = {}

    def warn(message):
        if message not in warnings:
            warnings.append(message)

    def add(name, version, scope='runtime', origin='manifest', key=None, offset=None, alias=False):
        canonical = _deps_normalize_name(ecosystem, name)
        if canonical is None:
            return
        if offset is None:
            offset = positions.get(key)
        metadata = {'ecosystem': ecosystem, 'name': canonical, 'version': _deps_safe_version(version), 'scope': scope, 'source': origin, 'alias': alias, 'location_precision': 'line' if offset is not None else 'file'}
        _deps_validate_dependency(metadata)
        records.append({'dependency': metadata, 'offset': offset})

    def requirement(value, scope='runtime', offset=None):
        if not isinstance(value, str):
            raise ValueError('Python-Abhängigkeiten müssen Zeichenketten sein.')
        text = _deps_re.split('\\s+#', value, maxsplit=1)[0].strip()
        match = _deps_re.match('^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\\[[A-Za-z0-9_,. -]+\\])?\\s*(.*)$', text)
        if not match:
            warn('Eine nicht unterstützte Anforderung wurde ausgelassen; kein Aufruf externer Quellen.')
            return
        name, tail = match.groups()
        if tail and (not tail.startswith(('<', '>', '=', '!', '~', ';', '@', '('))):
            warn('Eine nicht unterstützte Anforderung wurde ausgelassen; kein Aufruf externer Quellen.')
            return
        conditional = ';' in tail
        version = tail.split(';', 1)[0].split(' --', 1)[0].strip()
        add(name, version, 'conditional' if conditional and scope == 'runtime' else scope, offset=offset)
    if kind == 'requirements':
        scope = 'constraint' if str(path).replace('\\', '/').rsplit('/', 1)[-1].startswith('constraints') else 'runtime'
        lines = source.splitlines(keepends=True)
        offset, pending, begin = (0, '', 0)
        for line in lines:
            if not pending:
                begin = offset
            offset += len(line)
            text = line.strip()
            if text.endswith('\\'):
                pending += text[:-1] + ' '
                continue
            text = pending + text
            pending = ''
            if not text or text.startswith('#'):
                continue
            if text.startswith('-'):
                warn('pip-Optionen, Includes und editierbare Anforderungen werden nicht aufgelöst oder ausgeführt.')
                continue
            requirement(text, scope, begin)
        if pending:
            warn('Unvollständige Zeilenfortsetzung wurde ausgelassen.')
    elif kind in {'npm_package', 'npm_lock', 'pipfile_lock'}:
        data, positions = _deps_json_with_positions(source)
        if kind == 'npm_package':
            for section, scope in (('dependencies', 'runtime'), ('devDependencies', 'development'), ('optionalDependencies', 'optional'), ('peerDependencies', 'peer')):
                dependencies = data.get(section, {})
                if not isinstance(dependencies, dict):
                    raise ValueError('npm-Abhängigkeitsbereich muss ein Objekt sein.')
                for name, version in dependencies.items():
                    if not isinstance(version, str):
                        raise ValueError('npm-Abhängigkeiten benötigen Zeichenketten.')
                    alias = _deps_re.fullmatch('npm:((?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+)(?:@(.+))?', version)
                    if alias:
                        add(alias.group(1), alias.group(2), scope, key=(section, name), alias=True)
                    else:
                        add(name, version, scope, key=(section, name))
        elif kind == 'pipfile_lock':
            for section, scope in (('default', 'runtime'), ('develop', 'development')):
                dependencies = data.get(section, {})
                if not isinstance(dependencies, dict):
                    raise ValueError('Pipfile-Lockbereich muss ein Objekt sein.')
                for name, options in dependencies.items():
                    if not isinstance(options, dict):
                        raise ValueError('Ungültiger Pipfile-Lockeintrag.')
                    add(name, options.get('version'), 'conditional' if scope == 'runtime' and options.get('markers') else scope, 'lockfile', key=(section, name))
        else:
            version = data.get('lockfileVersion')
            if type(version) is not int or version not in {1, 2, 3}:
                raise ValueError('Unterstützt werden npm-Lockfile-Versionen 1, 2 und 3.')
            if version in {2, 3}:
                packages = data.get('packages')
                if not isinstance(packages, dict):
                    raise ValueError('npm-Lockfile benötigt ein packages-Objekt.')
                for locator, entry in packages.items():
                    if not isinstance(entry, dict):
                        raise ValueError('Ungültiger npm-Lockeintrag.')
                    if not locator.startswith('node_modules/') and '/node_modules/' not in locator:
                        continue
                    name = locator.rsplit('node_modules/', 1)[-1]
                    scope = 'development' if entry.get('dev') is True else 'optional' if entry.get('optional') is True else 'unknown'
                    add(name, entry.get('version'), scope, 'lockfile', key=('packages', locator))
            else:
                root_dependencies = data.get('dependencies', {})
                if not isinstance(root_dependencies, dict):
                    raise ValueError('npm-Lockfile benötigt ein dependencies-Objekt.')
                stack = [(root_dependencies, ('dependencies',))]
                while stack:
                    dependencies, path_key = stack.pop()
                    for name, entry in dependencies.items():
                        if not isinstance(entry, dict):
                            raise ValueError('Ungültiger npm-Lockeintrag.')
                        scope = 'development' if entry.get('dev') is True else 'optional' if entry.get('optional') is True else 'unknown'
                        add(name, entry.get('version'), scope, 'lockfile', key=path_key + (name,))
                        nested = entry.get('dependencies', {})
                        if not isinstance(nested, dict):
                            raise ValueError('Ungültige verschachtelte npm-Abhängigkeiten.')
                        if nested:
                            stack.append((nested, path_key + (name, 'dependencies')))
    elif kind == 'pyproject':
        try:
            import tomllib as _deps_tomllib
        except ImportError:
            raise _deps_Unavailable('pyproject.toml benötigt Python 3.11+ (tomllib); keine Zusatzpakete werden geladen.') from None
        try:
            data = _deps_tomllib.loads(source)
        except ValueError:
            raise ValueError('Ungültige TOML-Syntax im Manifest.') from None
        project, build = (data.get('project', {}), data.get('build-system', {}))
        if not isinstance(project, dict) or not isinstance(build, dict):
            raise ValueError('Ungültige pyproject-Tabellen.')
        for dependencies, scope in ((project.get('dependencies', []), 'runtime'), (build.get('requires', []), 'build')):
            if not isinstance(dependencies, list):
                raise ValueError('pyproject-Abhängigkeiten müssen Listen sein.')
            for item in dependencies:
                requirement(item, scope)
        optional = project.get('optional-dependencies', {})
        if not isinstance(optional, dict):
            raise ValueError('Ungültige optionale pyproject-Abhängigkeiten.')
        for dependencies in optional.values():
            if not isinstance(dependencies, list):
                raise ValueError('Optionale Abhängigkeiten müssen Listen sein.')
            for item in dependencies:
                requirement(item, 'optional')
        if project.get('dynamic'):
            warn('Dynamische pyproject-Metadaten werden nicht aufgelöst.')
        tools = data.get('tool', {})
        if not isinstance(tools, dict):
            raise ValueError('Ungültige pyproject-tool-Tabelle.')
        if 'dependency-groups' in data or 'poetry' in tools:
            warn('Dependency-Groups und Poetry-spezifische Bereiche werden in dieser Version nicht ausgewertet.')
    else:
        if _deps_re.search('<!\\s*(?:DOCTYPE|ENTITY)\\b', source, _deps_re.I):
            raise ValueError('XML mit DTD-/Entity-Deklarationen wird nicht verarbeitet.')
        try:
            root = _deps_ET.fromstring(source)
        except _deps_ET.ParseError:
            raise ValueError('Ungültige XML-Syntax im Manifest.') from None
        if root.tag not in {'project', '{http://maven.apache.org/POM/4.0.0}project'}:
            raise ValueError('Maven-Manifest benötigt ein project-Wurzelelement.')
        prefix = '{http://maven.apache.org/POM/4.0.0}' if root.tag.startswith('{') else ''

        def children(element, name):
            return element.findall(prefix + name)

        def text(element, name):
            values = children(element, name)
            return (values[0].text or '').strip() if len(values) == 1 else ''

        def dependencies(parent, forced_scope=None):
            for container in children(parent, 'dependencies'):
                for dependency in children(container, 'dependency'):
                    name = text(dependency, 'groupId') + ':' + text(dependency, 'artifactId')
                    scope = forced_scope or {'test': 'development', 'provided': 'provided', 'system': 'provided', 'compile': 'runtime', 'runtime': 'runtime', 'import': 'managed', '': 'runtime'}.get(text(dependency, 'scope'), 'unknown')
                    if not forced_scope and text(dependency, 'optional') == 'true':
                        scope = 'optional'
                    add(name, text(dependency, 'version'), scope)
        dependencies(root)
        for manager in children(root, 'dependencyManagement'):
            dependencies(manager, 'managed')
        for container in children(root, 'profiles'):
            for profile in children(container, 'profile'):
                dependencies(profile, 'conditional')
                for manager in children(profile, 'dependencyManagement'):
                    dependencies(manager, 'managed')
        warn('Maven-Parents, Properties, Plugin-Abhängigkeiten und aktive Profile werden nicht aufgelöst.')
    return {'records': records, 'warnings': warnings}

pqdeps = _SimpleNamespace(
    CATALOG=_deps_CATALOG,
    CATALOG_VERSION=_deps_CATALOG_VERSION,
    DEPENDENCY_GUIDANCE=_deps_DEPENDENCY_GUIDANCE,
    DEPENDENCY_NOTE=_deps_DEPENDENCY_NOTE,
    ECOSYSTEM_LABELS=_deps_ECOSYSTEM_LABELS,
    FIELDS=_deps_FIELDS,
    KINDS=_deps_KINDS,
    MAX_DEPTH=_deps_MAX_DEPTH,
    MAX_JSON_ITEMS=_deps_MAX_JSON_ITEMS,
    SCOPE_LABELS=_deps_SCOPE_LABELS,
    SOURCE_LABELS=_deps_SOURCE_LABELS,
    Unavailable=_deps_Unavailable,
    describe=_deps_describe,
    json_with_positions=_deps_json_with_positions,
    manifest_kind=_deps_manifest_kind,
    normalize_name=_deps_normalize_name,
    parse_manifest=_deps_parse_manifest,
    safe_version=_deps_safe_version,
    validate_dependency=_deps_validate_dependency,
)


import argparse
import ast
from bisect import bisect_right
from collections import Counter
from datetime import datetime, timezone
import fnmatch
import heapq
import html
import io
import json
import os
from pathlib import Path
import re
import sys
import tokenize
from urllib.parse import quote

VERSION = "0.10.0"
SOURCE_CONTEXT_RADIUS = 5
MAX_CONTEXT_LINE_CHARS = 4000
EXTENSIONS = {".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
              ".mts", ".cts", ".java", ".go", ".c", ".h", ".cc", ".cpp", ".cxx",
              ".hpp", ".hxx", ".cs", ".rs", ".php", ".phtml", ".php3", ".php4",
              ".php5", ".phps", ".rb", ".rake", ".gemspec", ".dart"}
SOURCE_FILENAMES = {"Gemfile", "Rakefile"}
PHP_EXTENSIONS = {".php", ".phtml", ".php3", ".php4", ".php5", ".phps"}
RUBY_EXTENSIONS = {".rb", ".rake", ".gemspec"}
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
             "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", "target"}
LABELS = {"migration_review": "PQC-Migration prüfen", "pqc_reference": "PQC-Verweis",
          "legacy_pqc_reference": "PQC-Vorläufer prüfen", "classical_weakness": "Klassische Schwäche prüfen",
          "context_review": "Kontext prüfen", "dependency_review": "Bibliothek prüfen"}
NOTES = {
    "dependency_review": pqdeps.DEPENDENCY_NOTE,
    "migration_review": "Klassische asymmetrische Kryptografie: gegen hinreichend leistungsfähige Quantencomputer nicht resistent. Einsatz und Migrationsbedarf prüfen.",
    "pqc_reference": "PQC-Bezeichnung gefunden. Das belegt weder korrekte Implementierung noch quantensichere Gesamtsicherheit.",
    "legacy_pqc_reference": "Vorläufer-/Familienname gefunden. Nicht automatisch mit dem standardisierten ML-KEM, ML-DSA oder SLH-DSA gleichsetzen.",
    "classical_weakness": "MD5/SHA-1 sind für kollisionsresistente Anwendungen ungeeignet. Verwendungszweck prüfen; dies ist kein spezifischer Post-Quanten-Befund.",
    "context_review": "Symmetrische Kryptografie, Hashfunktion oder Schlüsselableitung: Parameter und Einsatzzweck prüfen. Nicht pauschal als quantenunsicher eingestuft.",
}
GUIDANCE = {
    "dependency_review": pqdeps.DEPENDENCY_GUIDANCE,
    "migration_review": "Einsatzstelle und Verantwortliche erfassen. Signaturen, Schlüsselaustausch und Verschlüsselung getrennt bewerten. Für Signaturen geeignete ML-DSA/SLH-DSA-Unterstützung, für die Etablierung gemeinsamer Schlüssel ML-KEM im passenden Protokoll prüfen. Kein automatischer Austausch einzelner API-Aufrufe.",
    "pqc_reference": "Prüfen, ob dies ausführbarer Code, eine Konfiguration oder nur eine Planungsbezeichnung ist. Bibliotheksversion, konkrete Parameter und Protokollintegration erfassen; anschließend Interoperabilität und Implementierung testen.",
    "legacy_pqc_reference": "Bibliotheksversion und genaue Algorithmusvariante ermitteln. Prüfen, ob bereits eine standardisierte Variante verwendet wird oder noch ein früherer Entwurf. Namen allein belegen keine Standardkonformität.",
    "classical_weakness": "Verwendungszweck feststellen: etwa Signatur, Fingerabdruck, HMAC oder reine Prüfsumme. Bei benötigter Kollisionsresistenz einen geeigneten aktuellen Hash und die Kompatibilität des Gesamtsystems prüfen.",
    "context_review": "Parameter, Betriebsart, Schlüssellänge, Zufallszahlen und Lebensdauer der geschützten Daten erfassen. Aus dem Algorithmusnamen allein lässt sich keine abschließende Sicherheitsbewertung ableiten.",
}
LIMITATIONS = [
    "Statische Fundstellen sind kein Nachweis tatsächlicher Laufzeitnutzung oder vollständiger Sicherheit.",
    "Python: ausgewählte APIs und Import-Aliasse; keine vollständige Datenfluss-, Typ- oder Erreichbarkeitsanalyse.",
    "Andere Sprachen: Textheuristik ohne Syntax-/Typanalyse; Kommentare werden bestmöglich ausgeblendet.",
    "PHP: begrenzte Textheuristik; auch HTML, eingebettetes JavaScript und Zeichenketten können Treffer erzeugen. Kein PHP-Parser, keine Composer-, Heredoc-/Nowdoc- oder Datenflussanalyse.",
    "Ruby/Dart und weitere Textsprachen: begrenzte Namensmuster, keine Framework-/Schwachstellenprüfung. Ruby-Blockkommentare, Interpolation, Regex- und Raw-Literale werden nicht vollständig verstanden.",
    "Nur ausgewählte direkt angegebene Schlüsselgrößen und Parameter; kein Nachweis gültiger oder ausreichend starker Schlüssel.",
    "Java/JavaScript/TypeScript: begrenzte API-Heuristik und einfache Bindungen; keine vollständige Syntax-, Typ- oder Kontrollflussanalyse. Templates, komplexe Aliasse und dynamische Werte bleiben offen.",
    "Nur ausgewählte lokale Abhängigkeitsdeklarationen und Lockfile-Einträge; keine Installation, Auflösung, CVE-Prüfung oder Bestätigung tatsächlicher Laufzeitnutzung.",
    "Keine Analyse von Binärdateien, Zertifikaten, TLS oder Protokollkombinationen.",
    "Nicht erkannte oder übersprungene Dateien können weitere Kryptografie enthalten. Kein Compliance-Zertifikat.",
]

# Ordered patterns: specific PQC/hybrid names win ties and enclose classical substrings.
TOKEN_RULES = [
    ("Hybrid-PQC", "pqc_reference", r"\b(?:X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024)\b"),
    ("ML-KEM", "pqc_reference", r"\bml[-_]?kem(?:[-_]?(?:512|768|1024))?\b"),
    ("ML-DSA", "pqc_reference", r"\bml[-_]?dsa(?:[-_]?(?:44|65|87))?\b"),
    ("SLH-DSA", "pqc_reference", r"\bslh[-_]?dsa(?:[-_][A-Za-z0-9]+)*\b"),
    ("FrodoKEM", "pqc_reference", r"\bFrodoKEM(?:[-_]?(?:640|976|1344)(?:[-_]?(?:AES|SHAKE))?)?\b"),
    ("Classic McEliece", "pqc_reference", r"\b(?:Classic[-_ ]?McEliece|mceliece\d+f?)\b"),
    ("XMSS/LMS", "pqc_reference", r"\b(?:XMSS(?:MT)?(?:[-_][A-Za-z0-9]+)*|LMS(?:[-_][A-Za-z0-9]+)*|HSS/LMS)\b"),
    ("Kyber/Dilithium/SPHINCS+", "legacy_pqc_reference",
     r"\b(?:X25519Kyber768Draft00|Kyber(?:512|768|1024)?|Dilithium[235]?|SPHINCS\+?)\b"),
    ("RSA", "migration_review", r"\b(?:RSA|RS(?:256|384|512)|PS(?:256|384|512)|Rsa(?:Private|Public)Key|RSA_(?:new|generate_key_ex|sign|verify|public_encrypt|private_decrypt))\b"),
    ("ECC", "migration_review", r"\b(?:ECDSA|ECDH|Ed25519|Ed448|X25519|X448|ECC|ES(?:256|384|512))\b|\belliptic\s*\.\s*P(?:224|256|384|521)\b"),
    ("DSA", "migration_review", r"\b(?:DSA|DSA_(?:new|generate_key|sign|verify))\b"),
    ("DH", "migration_review", r"\b(?:DiffieHellman|createDiffieHellman|DH_(?:new|generate_key|compute_key))\b"),
    ("MD5/SHA-1", "classical_weakness", r"\b(?:MD5|SHA[-_]?1|SHA1_(?:Init|Update|Final))\b"),
    ("AES/ChaCha20", "context_review", r"\b(?:AES(?:[-_]?(?:128|192|256)|GCM|CCM|SIV|OCB3|GCMSIV)?|ChaCha20(?:Poly1305)?)\b"),
    ("SHA-2/SHA-3", "context_review", r"\b(?:SHA[-_]?(?:224|256|384|512)|SHA3[-_]?(?:224|256|384|512))\b"),
    ("HMAC-SHA-2", "context_review", r"\bHS(?:256|384|512)\b"),
]
TOKEN_RULES = [(a, c, re.compile(p, re.I)) for a, c, p in TOKEN_RULES]


def token_findings(text):
    # Merge lazy match streams instead of comparing each hit with every prior hit.
    # This keeps long generated/minified lines with many matches practical.
    def matches(priority, rule):
        algorithm, category, pattern = rule
        for match in pattern.finditer(text):
            yield match.start(), priority, match.end(), algorithm, category
    last_end = -1
    for start, _, end, algorithm, category in heapq.merge(*(matches(i, rule) for i, rule in enumerate(TOKEN_RULES))):
        if start >= last_end:
            yield algorithm, category, start
            last_end = end


# Metadata extracted only from selected, resolved Python APIs. Never copy arguments.
ROLE_LABELS = {"unknown": "Einsatzzweck offen", "signature": "Signatur", "key_agreement": "Schlüsseletablierung",
               "encryption": "Verschlüsselung", "hashing": "Hashfunktion", "key_derivation": "Schlüsselableitung",
               "authentication": "Authentisierung"}
OPERATION_LABELS = {"reference": "API-Verweis", "key_generation": "Schlüsselerzeugung",
                    "parameter_generation": "Parametererzeugung", "key_loading": "Schlüssel laden",
                    "algorithm_selection": "Algorithmusauswahl", "signing": "Signieren", "verification": "Signatur prüfen",
                    "key_agreement": "Gemeinsamen Schlüssel ableiten", "encryption": "Verschlüsseln", "decryption": "Entschlüsseln",
                    "encapsulation": "Schlüssel kapseln", "decapsulation": "Schlüssel entkapseln", "hashing": "Hash berechnen",
                    "key_derivation": "Schlüssel ableiten", "token_signing": "Token erzeugen", "token_verification": "Token prüfen"}
PARAMETER_NAMES = {"public_exponent", "generator", "length", "iterations", "memory_cost", "lanes", "n", "r", "p"}


def empty_details():
    return {"crypto_role": "unknown", "operation": "reference", "key_size_bits": None,
            "key_size_origin": None, "parameters": {}}


def call_argument(node, name, position=None):
    if not isinstance(node, ast.Call):
        return None
    matches = [kw.value for kw in node.keywords if kw.arg == name]
    if len(matches) == 1:
        return matches[0]
    # Expanded arguments may change positions or supply a keyword; keep those unknown.
    if matches or any(kw.arg is None for kw in node.keywords):
        return None
    if position is not None and len(node.args) > position and not any(isinstance(arg, ast.Starred) for arg in node.args[:position + 1]):
        return node.args[position]
    return None


def positive_literal(node, maximum=2_147_483_647):
    return node.value if isinstance(node, ast.Constant) and type(node.value) is int and 0 < node.value <= maximum else None


def known_key_method(api):
    match = re.fullmatch(r"@pqscan:(RSA|DSA|ECC|Ed25519|Ed448|X25519|X448|DH|AESGCM|AESCCM|AESOCB3|AESSIV|AESGCMSIV|ChaCha20Poly1305):(private|public|parameters|symmetric)\.([A-Za-z_]+)", api)
    if not match:
        return None
    family, kind, method = match.groups()
    allowed = {}
    if family in {"RSA", "DSA", "ECC", "Ed25519", "Ed448"}:
        if kind == "private":
            allowed["sign"] = "signing"
        if kind == "public":
            allowed["verify"] = "verification"
    if family in {"DH", "X25519", "X448", "ECC"} and kind == "private":
        allowed["exchange"] = "key_agreement"
    if family == "RSA":
        if kind == "public":
            allowed["encrypt"] = "encryption"
        if kind == "private":
            allowed["decrypt"] = "decryption"
    if kind == "symmetric":
        allowed.update(encrypt="encryption", decrypt="decryption")
    if family == "DH" and kind == "parameters":
        allowed["generate_private_key"] = "key_generation"
    operation = allowed.get(method)
    return (family, kind, operation) if operation else None


def constructed_binding(api):
    if not api:
        return None
    prefix = "cryptography.hazmat.primitives.asymmetric."
    if api.startswith(prefix):
        tail = api[len(prefix):]
        mapping = {"rsa.generate_private_key": "RSA:private", "dsa.generate_private_key": "DSA:private",
                   "ec.generate_private_key": "ECC:private", "dh.generate_parameters": "DH:parameters"}
        for module, family in (("ed25519", "Ed25519"), ("ed448", "Ed448"), ("x25519", "X25519"), ("x448", "X448")):
            mapping[module + "." + family + "PrivateKey.generate"] = family + ":private"
            mapping[module + "." + family + "PrivateKey.from_private_bytes"] = family + ":private"
            mapping[module + "." + family + "PublicKey.from_public_bytes"] = family + ":public"
        if tail in mapping:
            return "@pqscan:" + mapping[tail]
    if re.fullmatch(r"@pqscan:(RSA|DSA|ECC|Ed25519|Ed448|X25519|X448|DH):private\.public_key", api):
        return api.removesuffix(":private.public_key") + ":public"
    if api == "@pqscan:DH:parameters.generate_private_key":
        return "@pqscan:DH:private"
    if api.startswith("cryptography.hazmat.primitives.ciphers.aead."):
        name = api.rsplit(".", 1)[-1]
        if name in {"AESGCM", "AESCCM", "AESOCB3", "AESSIV", "AESGCMSIV", "ChaCha20Poly1305"}:
            return "@pqscan:" + name + ":symmetric"
    return None


def describe_python_call(api, node):
    details = empty_details()
    operation, role = "reference", "unknown"
    key_argument = None
    size_node = None
    public_parameters = {}
    api = api.split(" [", 1)[0]
    member = api.rsplit(".", 1)[-1]
    known = known_key_method(api)
    if known:
        family, kind, operation = known
        role = ("signature" if operation in {"signing", "verification"} else
                "key_agreement" if operation in {"key_agreement", "key_generation"} else "encryption")
    elif api.startswith("cryptography.hazmat.primitives.asymmetric."):
        family = api.split(".")[4]
        role = {"dsa": "signature", "ed25519": "signature", "ed448": "signature",
                "dh": "key_agreement", "x25519": "key_agreement", "x448": "key_agreement"}.get(family, "unknown")
        if member in {"generate_private_key", "generate"}:
            operation = "key_generation"
        elif member == "generate_parameters":
            operation = "parameter_generation"
        elif member in {"from_private_bytes", "from_public_bytes"}:
            operation = "key_loading"
        elif family == "ec" and member in {"ECDSA", "ECDH"}:
            operation, role = "algorithm_selection", "signature" if member == "ECDSA" else "key_agreement"
        if api.endswith("rsa.generate_private_key"):
            size_node = call_argument(node, "key_size", 1)
            public_parameters["public_exponent"] = call_argument(node, "public_exponent", 0)
        elif api.endswith("dsa.generate_private_key"):
            size_node = call_argument(node, "key_size", 0)
        elif api.endswith("dh.generate_parameters"):
            size_node = call_argument(node, "key_size", 1)
            public_parameters["generator"] = call_argument(node, "generator", 0)
    elif re.fullmatch(r"Crypto(?:dome)?\.PublicKey\.(RSA|DSA|ECC)\.generate", api):
        operation = "key_generation"
        role = "signature" if ".DSA." in api else "unknown"
        if ".ECC." not in api:
            size_node = call_argument(node, "bits", 0)
        if ".RSA." in api:
            public_parameters["public_exponent"] = call_argument(node, "e")
    elif api.startswith(("cryptography.hazmat.primitives.ciphers.algorithms.", "cryptography.hazmat.primitives.ciphers.aead.")) or re.match(r"^Crypto(?:dome)?\.Cipher\.", api):
        role, operation = "encryption", "algorithm_selection"
        if member == "generate_key":
            operation = "key_generation"
            size_node = call_argument(node, "bit_length", 0)
        elif member != "new" or re.match(r"^Crypto(?:dome)?\.Cipher\.", api):
            key_argument = call_argument(node, "key", 0)
    elif api.startswith(("hashlib.", "cryptography.hazmat.primitives.hashes.", "Crypto.Hash.", "Cryptodome.Hash.")):
        role = "hashing"
        operation = "algorithm_selection" if ".hazmat." in api else "hashing"
    elif api.startswith("cryptography.hazmat.primitives.kdf."):
        role, operation = "key_derivation", "algorithm_selection"
        for parameter in PARAMETER_NAMES - {"public_exponent", "generator"}:
            public_parameters[parameter] = call_argument(node, parameter)
        # All supported cryptography KDF constructors take length by keyword.
    elif api in {"jwt.encode", "jwt.decode", "jose.jwt.encode", "jose.jwt.decode"}:
        role, operation = "authentication", "token_signing" if member == "encode" else "token_verification"
    elif api in {"oqs.KeyEncapsulation", "oqs.Signature"}:
        role, operation = ("key_agreement" if member == "KeyEncapsulation" else "signature"), "algorithm_selection"
    elif api.startswith(("pqcrypto.kem.", "pqcrypto.sign.")):
        kem = api.startswith("pqcrypto.kem.")
        role = "key_agreement" if kem else "signature"
        operation = {"generate_keypair": "key_generation", "encrypt": "encapsulation" if kem else "reference",
                     "decrypt": "decapsulation" if kem else "reference", "sign": "signing" if not kem else "reference",
                     "verify": "verification" if not kem else "reference"}.get(member, "reference")
    elif api.startswith(("nacl.signing.SigningKey", "nacl.public.PrivateKey")):
        role = "signature" if ".signing." in api else "key_agreement"
        operation = "key_generation" if member == "generate" else "key_loading"
    size = positive_literal(size_node, 1_000_000)
    if size is not None:
        details.update(key_size_bits=size, key_size_origin="integer_literal")
    elif isinstance(key_argument, ast.Constant) and type(key_argument.value) is bytes and 0 < len(key_argument.value) <= 125_000:
        details.update(key_size_bits=len(key_argument.value) * 8, key_size_origin="byte_literal_length")
    details.update(crypto_role=role, operation=operation)
    details["parameters"] = {name: value for name, argument in public_parameters.items() if (value := positive_literal(argument)) is not None}
    return details


def details_text(item):
    if item.get("dependency") is not None:
        return pqdeps.describe(item["dependency"])
    parts = ["Zweck: " + ROLE_LABELS.get(item.get("crypto_role", "unknown"), "Einsatzzweck offen"),
             "Vorgang: " + OPERATION_LABELS.get(item.get("operation", "reference"), "API-Verweis")]
    if item.get("key_size_bits") is not None:
        origin = "Länge eines Bytes-Literals" if item.get("key_size_origin") == "byte_literal_length" else "Zahlenliteral"
        parts.append(f"Schlüsselgröße: {item['key_size_bits']} Bit ({origin}; keine Sicherheitsbewertung)")
    else:
        parts.append("Schlüsselgröße: nicht direkt erfasst")
    if item.get("parameters"):
        parts.append("Explizite Parameter: " + ", ".join(f"{key}={value}" for key, value in sorted(item["parameters"].items())))
    return " · ".join(parts)


def explain_finding(item, language="de"):
    """Explain detection and classification without inventing application context."""
    method, category = item["method"], item["category"]
    if language == "en":
        detection = {"python_ast": "A selected cryptographic API call was recognized in the Python syntax tree",
                     "api_heuristic": "A supported Java/JavaScript/TypeScript API pattern was matched",
                     "text_heuristic": "A selected cryptographic name pattern was found in text",
                     "dependency_manifest": "A cataloged cryptography library declaration was found in a supported manifest"}[method]
        limitation = {"python_ast": "Static call recognition does not prove execution, reachability, correct parameters or secure integration.",
                      "api_heuristic": "This is a bounded API heuristic, not complete type, scope or data-flow analysis; execution is unverified.",
                      "text_heuristic": "The text may be code, documentation, a string or configuration. This does not confirm an API call or a vulnerability.",
                      "dependency_manifest": "A declaration does not establish installation, algorithm use, a vulnerable version or PQ readiness."}[method]
        assessment = {"migration_review": "Classical asymmetric cryptography needs PQ migration review because sufficiently capable quantum computers threaten these mathematical foundations.",
                      "classical_weakness": "MD5/SHA-1 require a purpose-specific classical security review. Collision-sensitive uses are unsuitable; this is not a specific PQ migration finding.",
                      "context_review": "A symmetric cipher, hash or KDF name is inventory evidence. Parameters and use need review; the name alone is not automatically quantum-insecure.",
                      "pqc_reference": "A PQC name is present; it does not prove standardized parameters, correct implementation or quantum-safe integration.",
                      "legacy_pqc_reference": "A pre-standard or family name was recognized. Verify the exact version rather than equating it with the finalized standard.",
                      "dependency_review": "This is library inventory, kept separate from detected algorithm use and vulnerability claims."}[category]
        next_step = {"migration_review": "Confirm the use, owner, protocol and cryptographic role before planning a tested PQ migration.",
                     "classical_weakness": "Determine whether this is password storage, a signature, HMAC, an identifier or a checksum, then assess the relevant design.",
                     "context_review": "Review the actual parameters, mode, key management, randomness and purpose in the surrounding application.",
                     "pqc_reference": "Verify the library version, parameter set, standard status and protocol integration.",
                     "legacy_pqc_reference": "Determine the precise algorithm revision and assess a migration to an appropriate standardized implementation.",
                     "dependency_review": "Confirm the actual installed version and usage separately; inventory is not a CVE or dependency-resolution result."}[category]
    else:
        detection = {"python_ast": "Ein ausgewählter Kryptografie-Aufruf wurde im Python-Syntaxbaum erkannt",
                     "api_heuristic": "Ein unterstütztes Java-/JavaScript-/TypeScript-API-Muster wurde erkannt",
                     "text_heuristic": "Ein ausgewähltes Kryptografie-Namensmuster wurde im Text gefunden",
                     "dependency_manifest": "Eine Kryptografie-Bibliothek aus dem lokalen Katalog wurde in einer unterstützten Projektdatei deklariert"}[method]
        limitation = {"python_ast": "Die statische Aufruferkennung belegt weder Ausführung und Erreichbarkeit noch gültige Parameter oder sichere Integration.",
                      "api_heuristic": "Begrenzte API-Heuristik ohne vollständige Typ-, Gültigkeitsbereichs- oder Datenflussanalyse. Die tatsächliche Ausführung ist ungeprüft.",
                      "text_heuristic": "Der Text kann Code, Dokumentation, Zeichenkette oder Konfiguration sein. Er bestätigt weder einen API-Aufruf noch eine Schwachstelle.",
                      "dependency_manifest": "Die Deklaration belegt weder Installation, Algorithmusnutzung, eine verwundbare Version noch PQC-Eignung."}[method]
        assessment, next_step = NOTES[category], GUIDANCE[category]
    return {"detection": detection + ": " + item["evidence"] + ".",
            "assessment": assessment, "limitations": limitation, "next_step": next_step}


def rationale_text(item):
    reason = item.get("rationale") or explain_finding(item)
    labels = {"detection": "Warum erkannt?", "assessment": "Warum diese Einordnung?",
              "limitations": "Was bleibt ungeprüft?", "next_step": "Nächster Schritt"}
    return "\n\n".join(labels[key] + "\n" + reason[key] for key in labels)


def finding(path, line, column, algorithm, category, method, evidence, variant=None):
    # API names / matched tokens only. Never include complete source lines or key material.
    review = bsi_profile.parameter_review(algorithm, variant)
    advisory_ids = [bsi_profile.MCELIECE_ADVISORY] if algorithm == "Classic McEliece" else (
        ["BSI-PARAMETER-REVIEW"] if review["status"] == "not_listed_in_reviewed_table" else [])
    bsi_note = bsi_profile.finding_note(algorithm, category)
    if review["status"] not in {"not_assessed", "special_advisory"}:
        bsi_note += " " + review["text"]
    item = {"file": str(path), "line": line, "column": column, "algorithm": algorithm,
            "category": category, "method": method, "evidence": evidence,
            "note": NOTES[category], "guidance": GUIDANCE[category], "context": path_context(path),
            "variant": variant, "parameter_review": review, "advisories": advisory_ids,
            "bsi_review": bsi_note, "dependency": None, "source_context": None, **empty_details()}
    item["rationale"] = explain_finding(item)
    return item


def path_context(path):
    """Path-based hint only; never assert that a finding is unreachable."""
    parts = Path(path).as_posix().lower().split("/")
    name = parts[-1]
    if any(p in {"test", "tests", "testing", "__tests__", "fixtures"} for p in parts[:-1]) or (
        name.startswith("test_") or name.endswith(("_test.py", "_test.go", "test.java", "tests.cs")) or
        ".test." in name or ".spec." in name
    ):
        return "test_hint"
    if any(p in {"example", "examples", "demo", "demos", "samples"} for p in parts[:-1]):
        return "example_hint"
    return "unknown"


class PythonScanner(ast.NodeVisitor):
    def __init__(self, path):
        self.path = path
        self.bindings = {}
        self.findings = []

    def resolve(self, node):
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return base + "." + node.attr if base else None
        if isinstance(node, ast.Call):
            return constructed_binding(self.resolve(node.func))
        return None

    def visit_Import(self, node):
        for alias in node.names:
            self.bindings[alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            # Relative imports and star imports cannot safely identify a known library.
            self.bindings[alias.asname or alias.name] = (
                f"{node.module}.{alias.name}" if node.module and not node.level and alias.name != "*" else None)

    def visit_Assign(self, node):
        self.visit(node.value)
        value = self.resolve(node.value)
        for target in node.targets:
            for child in ast.walk(target):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    self.bindings[child.id] = value if isinstance(target, ast.Name) else None

    def visit_AnnAssign(self, node):
        if node.value:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.bindings[node.target.id] = self.resolve(node.value)

    def invalidate_target(self, target):
        for part in ast.walk(target):
            if isinstance(part, ast.Name) and isinstance(part.ctx, (ast.Store, ast.Del)):
                self.bindings[part.id] = None

    def visit_AugAssign(self, node):
        self.visit(node.value)
        self.invalidate_target(node.target)

    def visit_Delete(self, node):
        for target in node.targets:
            self.invalidate_target(target)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.bindings[node.target.id] = self.resolve(node.value)

    def visit_For(self, node):
        self.visit(node.iter)
        self.invalidate_target(node.target)
        for statement in node.body + node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self.invalidate_target(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node):
        if node.type:
            self.visit(node.type)
        if node.name:
            self.bindings[node.name] = None
        for statement in node.body:
            self.visit(statement)
        if node.name:
            self.bindings[node.name] = None

    def visit_If(self, node):
        self.visit(node.test)
        original = self.bindings
        branches = []
        for statements in (node.body, node.orelse):
            self.bindings = dict(original)
            for statement in statements:
                self.visit(statement)
            branches.append(self.bindings)
        self.bindings = original
        for key in branches[0].keys() | branches[1].keys():
            left, right = branches[0].get(key), branches[1].get(key)
            self.bindings[key] = left if left == right else None

    def visit_comprehension_expression(self, node):
        original = self.bindings
        self.bindings = dict(original)
        for generator in node.generators:
            self.visit(generator.iter)
            self.invalidate_target(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.bindings = original

    visit_ListComp = visit_comprehension_expression
    visit_SetComp = visit_comprehension_expression
    visit_DictComp = visit_comprehension_expression
    visit_GeneratorExp = visit_comprehension_expression

    def scoped(self, node, args=None):
        old = self.bindings
        self.bindings = dict(old)
        # Python function locals shadow outer imports even before an assignment.
        if args is not None:
            def local_names(part):
                if isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    yield part.name
                    return
                if isinstance(part, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Lambda)):
                    return
                if isinstance(part, ast.ExceptHandler) and part.name:
                    yield part.name
                if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store):
                    yield part.id
                if isinstance(part, (ast.Import, ast.ImportFrom)):
                    for alias in part.names:
                        yield alias.asname or alias.name.split(".")[0]
                for child in ast.iter_child_nodes(part):
                    yield from local_names(child)
            for statement in node.body:
                for name in local_names(statement):
                    self.bindings[name] = None
            for arg in args.posonlyargs + args.args + args.kwonlyargs:
                self.bindings[arg.arg] = None
            for arg in (args.vararg, args.kwarg):
                if arg:
                    self.bindings[arg.arg] = None
        for statement in node.body:
            self.visit(statement)
        self.bindings = old

    def visit_FunctionDef(self, node):
        for part in node.decorator_list + node.args.defaults + [x for x in node.args.kw_defaults if x]:
            self.visit(part)
        self.bindings[node.name] = None
        self.scoped(node, node.args)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for part in node.bases + node.decorator_list:
            self.visit(part)
        self.bindings[node.name] = None
        self.scoped(node)

    def visit_Lambda(self, node):
        old = self.bindings
        self.bindings = dict(old)
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.bindings[arg.arg] = None
        for arg in (node.args.vararg, node.args.kwarg):
            if arg:
                self.bindings[arg.arg] = None
        self.visit(node.body)
        self.bindings = old

    def add(self, node, algorithm, category, evidence, variant=None):
        item = finding(self.path, node.lineno, node.col_offset + 1,
                       algorithm, category, "python_ast", evidence, variant)
        item.update(describe_python_call(evidence, node))
        self.findings.append(item)

    def visit_Call(self, node):
        name = self.resolve(node.func)
        if name:
            asymmetric = "cryptography.hazmat.primitives.asymmetric."
            families = {"rsa": "RSA", "dsa": "DSA", "dh": "DH", "ec": "ECC",
                        "ed25519": "Ed25519", "ed448": "Ed448", "x25519": "X25519", "x448": "X448"}
            known = known_key_method(name)
            if known:
                family, kind, operation = known
                algorithm = "AES/ChaCha20" if kind == "symmetric" else family
                category = "context_review" if kind == "symmetric" else "migration_review"
                evidence = "Statisch zugeordnetes " + family + "-Objekt: " + name.rsplit(".", 1)[-1]
                self.add(node, algorithm, category, evidence)
                self.findings[-1].update(describe_python_call(name, node))
            elif name.startswith(asymmetric):
                family = name[len(asymmetric):].split(".")[0]
                if family in families:
                    self.add(node, families[family], "migration_review", name)
            elif re.match(r"^Crypto(?:dome)?\.PublicKey\.(RSA|DSA|ECC)\.", name):
                self.add(node, name.split(".")[2], "migration_review", name)
            elif name.startswith("hashlib."):
                algo = name.split(".")[-1].lower()
                if algo in {"md5", "sha1"}:
                    self.add(node, algo.upper(), "classical_weakness", name)
                elif re.fullmatch(r"sha(?:224|256|384|512|3_(?:224|256|384|512))", algo):
                    self.add(node, algo.upper(), "context_review", name)
                elif algo == "new":
                    argument = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "name"), None)
                    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                        self.add_string(argument, argument.value, name)
            elif (name.startswith("cryptography.hazmat.primitives.ciphers.algorithms.") or
                  name.startswith("cryptography.hazmat.primitives.ciphers.aead.") or
                  re.match(r"^Crypto(?:dome)?\.Cipher\.", name)):
                for algorithm, category, _ in token_findings(name.split(".")[-2] if name.endswith((".new", ".generate_key")) else name.split(".")[-1]):
                    self.add(node, algorithm, category, name)
            elif name.startswith("cryptography.hazmat.primitives.hashes."):
                self.add_string(node, name.split(".")[-1], name)
            elif re.fullmatch(r"Crypto(?:dome)?\.Hash\.(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_(?:224|256|384|512))\.new", name):
                self.add_string(node, name.split(".")[-2], name)
            elif name in {"nacl.signing.SigningKey.generate", "nacl.signing.SigningKey"}:
                self.add(node, "Ed25519", "migration_review", name)
            elif name in {"nacl.public.PrivateKey.generate", "nacl.public.PrivateKey"}:
                self.add(node, "X25519", "migration_review", name)
            elif re.fullmatch(r"cryptography\.hazmat\.primitives\.kdf\.(?:hkdf\.HKDF|hkdf\.HKDFExpand|pbkdf2\.PBKDF2HMAC|scrypt\.Scrypt|argon2\.Argon2id)", name):
                self.add(node, name.split(".")[-1], "context_review", name)
            elif name in {"jwt.encode", "jwt.decode", "jose.jwt.encode", "jose.jwt.decode"}:
                for keyword in node.keywords:
                    if keyword.arg in {"algorithm", "algorithms"}:
                        values = keyword.value.elts if isinstance(keyword.value, (ast.List, ast.Tuple)) else [keyword.value]
                        for value in values:
                            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                                self.add_string(node, value.value, name)
            elif name in {"oqs.KeyEncapsulation", "oqs.Signature"}:
                argument = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "alg_name"), None)
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    self.add_string(node, argument.value, name)
            elif name.startswith(("pqcrypto.kem.", "pqcrypto.sign.")):
                self.add_string(node, name.split(".")[2], name)
        self.generic_visit(node)

    def add_string(self, node, value, api):
        for algorithm, category, start in token_findings(value):
            self.add(node, algorithm, category, api + " [Algorithmusbezeichnung]",
                     bsi_profile.recognized_variant(value[start:], algorithm))


def mask_comments(source, hash_comments=False, c_comments=True):
    """Mask // and /* */ comments while preserving newlines, offsets and strings.

    Best effort for C-like languages, not a full lexer (e.g. Rust raw strings).
    """
    chars = list(source)
    i = 0
    quote = None
    while i < len(source):
        if quote:
            if source[i] == "\\":
                i += 2
                continue
            if source[i] == quote:
                quote = None
            i += 1
        elif source[i] in "\"'`":
            quote = source[i]
            i += 1
        elif (c_comments and source.startswith("//", i)) or (hash_comments and source[i] == "#"):
            end = source.find("\n", i)
            end = len(source) if end < 0 else end
            chars[i:end] = " " * (end - i)
            i = end
        elif c_comments and source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = len(source) if end < 0 else end + 2
            for k in range(i, end):
                if chars[k] not in "\r\n":
                    chars[k] = " "
            i = end
        else:
            i += 1
    return "".join(chars)


# Selected Java and JavaScript API patterns, implemented without executing source.
# This lexer and the conservative bindings below are not a language parser/type checker.
JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
JAVA_CLASSES = {
    "KeyPairGenerator": "java.security.KeyPairGenerator", "Signature": "java.security.Signature",
    "MessageDigest": "java.security.MessageDigest", "KeyGenerator": "javax.crypto.KeyGenerator",
    "Cipher": "javax.crypto.Cipher", "KeyAgreement": "javax.crypto.KeyAgreement", "Mac": "javax.crypto.Mac",
    "RSAKeyGenParameterSpec": "java.security.spec.RSAKeyGenParameterSpec"}


def api_tokens(source, javascript=False):
    """Return tokens with original offsets. Templates/text blocks are opaque."""
    tokens, i = [], 0
    identifier = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
    number = re.compile(r"[0-9][0-9_]*")
    regex_after = {"=", "(", "[", "{", ",", ":", ";", "!", "?", "=>", "return", "throw", "case", "&&", "||"}
    while i < len(source):
        if source[i].isspace():
            i += 1
            continue
        start = i
        if source.startswith("//", i):
            end = source.find("\n", i + 2)
            i = len(source) if end < 0 else end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = len(source) if end < 0 else end + 2
            continue
        if not javascript and source.startswith('"""', i):
            end = source.find('"""', i + 3)
            i = len(source) if end < 0 else end + 3
            tokens.append(("opaque", "", start, i))
            continue
        if source[i] in "\"'`":
            quote_char = source[i]
            i += 1
            escaped = False
            while i < len(source):
                if source[i] == "\\":
                    escaped = True
                    i += 2
                elif source[i] == quote_char:
                    i += 1
                    break
                else:
                    i += 1
            else:
                return None
            value = source[start + 1:i - 1]
            # Do not decode escapes/interpolation into presumed algorithm names.
            tokens.append(("str" if quote_char != "`" and not escaped else "opaque", value, start, i))
            continue
        if javascript and source[i] == "/" and (not tokens or tokens[-1][1] in regex_after):
            i += 1
            char_class = False
            while i < len(source) and source[i] not in "\r\n":
                char = source[i]
                if char == "\\":
                    i += 2
                    continue
                if char == "[":
                    char_class = True
                elif char == "]":
                    char_class = False
                elif char == "/" and not char_class:
                    i += 1
                    while i < len(source) and source[i].isalpha():
                        i += 1
                    break
                i += 1
            tokens.append(("opaque", "", start, i))
            continue
        match = identifier.match(source, i)
        if match:
            i = match.end()
            tokens.append(("id", match.group(), start, i))
        else:
            match = number.match(source, i)
            if match:
                i = match.end()
                tokens.append(("number", match.group(), start, i))
            else:
                operator = next((op for op in ("...", "||=", "&&=", "??=", "=>", "?.", "==", "!=", "+=", "-=", "*=", "/=", "++", "--", "&&", "||", "**") if source.startswith(op, i)), source[i])
                i += len(operator)
                tokens.append(("punct", operator, start, i))
        if len(tokens) > 250_000:
            return None
    return tokens


def token_pairs(tokens):
    stack, pairs = [], {}
    closing = {")": "(", "]": "[", "}": "{"}
    for i, token in enumerate(tokens):
        if token[0] != "punct":
            continue
        value = token[1]
        if value in {"(", "[", "{"}:
            stack.append(i)
        elif value in closing:
            if not stack or tokens[stack[-1]][1] != closing[value]:
                return None
            opening = stack.pop()
            pairs[opening] = i
            pairs[i] = opening
    return None if stack else pairs


def token_segments(tokens, pairs, start, stop):
    """Split a delimited range on top-level commas; preserve nested expressions."""
    result, begin, i = [], start, start
    while i < stop:
        value = tokens[i][1]
        if tokens[i][0] == "punct" and value in {"(", "[", "{"}:
            i = pairs[i] + 1
            continue
        if tokens[i][0] == "punct" and value == ",":
            result.append((begin, i))
            begin = i + 1
        i += 1
    if begin < stop:
        result.append((begin, stop))
    return result


def token_string(tokens, segment):
    if segment and segment[1] == segment[0] + 1 and tokens[segment[0]][0] == "str":
        return tokens[segment[0]][1]
    return None


def token_integer(tokens, segment, maximum=1_000_000):
    if segment and segment[1] == segment[0] + 1:
        kind, value, _, _ = tokens[segment[0]]
        if kind == "number" and len(value) <= 12 and re.fullmatch(r"[0-9]+(?:_[0-9]+)*", value):
            number = int(value.replace("_", ""))
            if 0 < number <= maximum:
                return number
    return None


def token_object(tokens, pairs, segment):
    if not segment or tokens[segment[0]][1] != "{" or pairs.get(segment[0]) != segment[1] - 1:
        return None
    properties = {}
    for start, stop in token_segments(tokens, pairs, segment[0] + 1, segment[1] - 1):
        if stop < start + 3 or tokens[start][0] not in {"id", "str"} or tokens[start + 1][1] != ":":
            return None  # spreads, getters, shorthand and computed properties are ambiguous
        name = tokens[start][1]
        if name in properties:
            return None
        properties[name] = (start + 2, stop)
    return properties


def api_algorithm(value):
    """Whitelist complete algorithm designators. Never return arbitrary string values."""
    if not isinstance(value, str) or len(value) > 128:
        return None
    base = value.split("/", 1)[0]
    upper = base.upper().replace("_", "-")
    role = "unknown"
    if upper in {"RSA", "RSA-PSS", "RSASSA-PSS", "RSA-OAEP", "RSASSA-PKCS1-V1-5"} or re.fullmatch(r"(?:RSA-SHA(?:1|224|256|384|512)|SHA(?:1|224|256|384|512)WITHRSA)", upper):
        algorithm, category = "RSA", "migration_review"
        if upper == "RSA-OAEP":
            role = "encryption"
        elif upper != "RSA":
            role = "signature"
    elif upper in {"EC", "ECC", "ECDH", "ECDSA", "ED25519", "ED448", "X25519", "X448"} or re.fullmatch(r"SHA(?:1|224|256|384|512)WITHECDSA", upper):
        algorithm, category = "ECC", "migration_review"
        role = "key_agreement" if upper in {"ECDH", "X25519", "X448"} else ("unknown" if upper in {"EC", "ECC"} else "signature")
    elif upper == "DSA" or re.fullmatch(r"SHA(?:1|224|256|384|512)WITHDSA", upper):
        algorithm, category, role = "DSA", "migration_review", "signature"
    elif upper in {"DH", "DIFFIEHELLMAN"}:
        algorithm, category, role = "DH", "migration_review", "key_agreement"
    elif re.fullmatch(r"AES(?:-(?:128|192|256))?(?:-(?:GCM|CCM|CBC|CTR|ECB|OCB))?|CHACHA20(?:-?POLY1305)?", upper):
        algorithm, category, role = "AES/ChaCha20", "context_review", "encryption"
    elif upper in {"MD5", "SHA1", "SHA-1"}:
        algorithm, category, role = "MD5/SHA-1", "classical_weakness", "hashing"
    elif re.fullmatch(r"SHA-?(?:224|256|384|512)|SHA3-?(?:224|256|384|512)", upper):
        algorithm, category, role = "SHA-2/SHA-3", "context_review", "hashing"
    elif re.fullmatch(r"HMACSHA-?(?:224|256|384|512)", upper):
        algorithm, category, role = "HMAC-SHA-2", "context_review", "authentication"
    elif upper in {"HMAC", "PBKDF2", "HKDF"}:
        algorithm, category = upper, "context_review"
        role = "authentication" if upper == "HMAC" else "key_derivation"
    else:
        matches = [(a, c) for a, c, pattern in TOKEN_RULES if pattern.fullmatch(base) and c in {"pqc_reference", "legacy_pqc_reference"}]
        if not matches:
            return None
        algorithm, category = matches[0]
        if algorithm in {"ML-KEM", "FrodoKEM", "Classic McEliece", "Hybrid-PQC"}:
            role = "key_agreement"
        elif algorithm in {"ML-DSA", "SLH-DSA", "XMSS/LMS"}:
            role = "signature"
    return algorithm, category, bsi_profile.recognized_variant(base, algorithm), role


def shadowed_api_names(tokens, pairs, names, ignored):
    """Whole-file invalidation is intentionally conservative; this is not scope analysis."""
    shadowed = set()
    assignments = {"=", "+=", "-=", "*=", "/=", "||=", "&&=", "??=", "++", "--"}
    for i, token in enumerate(tokens):
        if i in ignored or token[0] != "id" or token[1] not in names:
            continue
        previous = tokens[i - 1][1] if i else ""
        following = tokens[i + 1][1] if i + 1 < len(tokens) else ""
        if previous != "." and (previous in {"const", "let", "var", "function", "class", "interface", "enum"} or following in assignments | {"=>"}):
            shadowed.add(token[1])
        # Property writes can replace an imported module method or Web Crypto API.
        j = i + 1
        while j + 1 < len(tokens) and tokens[j][1] == "." and tokens[j + 1][0] == "id":
            j += 2
        if j > i + 1 and j < len(tokens) and tokens[j][1] in assignments:
            shadowed.add(token[1])
    for i, token in enumerate(tokens[:-1]):
        if i in ignored or token[1] not in {"const", "let", "var"} or tokens[i + 1][1] not in {"{", "["}:
            continue
        end = pairs.get(i + 1)
        if end is not None and end + 1 < len(tokens) and tokens[end + 1][1] == "=":
            shadowed.update(tokens[j][1] for j in range(i + 2, end) if tokens[j][0] == "id" and tokens[j][1] in names)
    controls = {"if", "while", "for", "switch", "with", "synchronized"}
    for opening, closing in pairs.items():
        if opening > closing or tokens[opening][1] != "(" or opening in ignored:
            continue
        after = closing + 1
        # Optional TypeScript return type or Java throws declaration (bounded).
        if after < len(tokens) and tokens[after][1] in {":", "throws"}:
            after += 1
            while after < min(len(tokens), closing + 15) and tokens[after][1] not in {"{", "=>", ";", "="}:
                after += 1
        previous = tokens[opening - 1][1] if opening else ""
        if after < len(tokens) and tokens[after][1] in {"{", "=>"} and previous not in controls:
            shadowed.update(tokens[j][1] for j in range(opening + 1, closing) if tokens[j][0] == "id" and tokens[j][1] in names)
    return shadowed


def api_imports(tokens, pairs, javascript):
    bindings, ignored, foreign_names = {}, set(), set()
    values = [token[1] for token in tokens]
    for i, token in enumerate(tokens):
        if token[0] != "id" or token[1] != "import":
            continue
        end = next((j for j in range(i + 1, min(len(tokens), i + 150)) if values[j] == ";"), None)
        if javascript:
            if i + 1 >= len(tokens) or values[i + 1] in {"(", "."} or tokens[i + 1][0] == "str":
                continue
            search_stop = min(len(tokens) - 1, i + 100, end if end is not None else len(tokens))
            from_index = next((j for j in range(i + 1, search_stop) if values[j] == "from" and tokens[j + 1][0] == "str"), None)
            if from_index is None:
                continue
            stop = from_index + 2
            ignored.update(range(i, stop))
            node_crypto = values[from_index + 1] in {"crypto", "node:crypto"} and values[i + 1] != "type"
            items = []
            if tokens[i + 1][0] == "id" and values[i + 1] != "type":
                items.append((values[i + 1], "node:crypto"))
            for j in range(i + 1, from_index):
                if values[j] == "*" and j + 2 < from_index and values[j + 1] == "as":
                    items.append((values[j + 2], "node:crypto"))
                if values[j] == "{" and j in pairs and pairs[j] < from_index:
                    for start, finish in token_segments(tokens, pairs, j + 1, pairs[j]):
                        if finish == start + 1 and tokens[start][0] == "id":
                            items.append((values[start], "node:crypto." + values[start]))
                        elif finish == start + 3 and values[start + 1] == "as":
                            items.append((values[start + 2], "node:crypto." + values[start]))
            for local, canonical in items:
                if node_crypto:
                    bindings[local] = canonical
                else:
                    foreign_names.add(local)
        elif end is not None:
            ignored.update(range(i, end + 1))
            full = "".join(values[i + 1:end])
            for name, canonical in JAVA_CLASSES.items():
                if full == canonical:
                    bindings[name] = canonical
                elif full.endswith("." + name):
                    foreign_names.add(name)
    if javascript:
        # Simple CommonJS namespace and destructuring declarations only.
        for i in range(len(tokens) - 5):
            if values[i] not in {"const", "let", "var"}:
                continue
            first = i + 1
            if tokens[first][0] == "id":
                equals = first + 1
                names = [(values[first], "node:crypto")]
            elif values[first] == "{" and first in pairs:
                equals = pairs[first] + 1
                names = []
                for start, stop in token_segments(tokens, pairs, first + 1, pairs[first]):
                    if stop == start + 1 and tokens[start][0] == "id":
                        names.append((values[start], "node:crypto." + values[start]))
                    elif stop == start + 3 and values[start + 1] == ":":
                        names.append((values[start + 2], "node:crypto." + values[start]))
                    else:
                        names = []
                        break
            else:
                continue
            if (equals + 4 < len(tokens) and values[equals:equals + 3] == ["=", "require", "("] and
                    pairs.get(equals + 2) == equals + 4 and tokens[equals + 3][0] == "str"):
                if values[equals + 3] in {"node:crypto", "crypto"}:
                    ignored.update(range(i, equals + 5))
                    for local, canonical in names:
                        bindings[local] = canonical
                else:
                    foreign_names.update(name for name, _ in names)
    names = set(bindings) | foreign_names | ({"crypto", "window", "globalThis", "require"} if javascript else {"java", "javax"})
    blocked = shadowed_api_names(tokens, pairs, names, ignored) | foreign_names
    if javascript and "require" in blocked:
        # A custom require invalidates CommonJS resolutions, conservatively all Node bindings.
        blocked.update(bindings)
    return {name: canonical for name, canonical in bindings.items() if name not in blocked}, blocked


def scan_api_patterns(path, source):
    """Return heuristic findings plus exact algorithm-literal spans replaced in fallback."""
    javascript = Path(path).suffix.lower() in JS_EXTENSIONS
    if not javascript and Path(path).suffix.lower() != ".java":
        return [], []
    tokens = api_tokens(source, javascript)
    if tokens is None:
        return [], []
    pairs = token_pairs(tokens)
    if pairs is None:
        return [], []
    bindings, blocked = api_imports(tokens, pairs, javascript)
    line_starts = [0] + [match.end() for match in re.finditer("\n", source)]
    results, covered, objects = [], [], {}
    values = [token[1] for token in tokens]

    def add(index, designator, api, role=None, operation="algorithm_selection", size=None, parameters=None, literal=None):
        if designator is None:
            return None
        algorithm, category, variant, hint = designator
        offset = tokens[index][2]
        line_index = bisect_right(line_starts, offset) - 1
        item = finding(path, line_index + 1, offset - line_starts[line_index] + 1, algorithm, category,
                       "api_heuristic", api + " [API-Muster]", variant)
        item.update(crypto_role=role or hint, operation=operation, key_size_bits=size,
                    key_size_origin="integer_literal" if size is not None else None, parameters=parameters or {})
        results.append(item)
        if literal:
            covered.append((tokens[literal[0]][2], tokens[literal[1] - 1][3]))
        return item

    for i, token in enumerate(tokens):
        value = token[1]
        if not javascript:
            if (token[0] == "punct" and value in {"{", "}"}) or value in {"if", "for", "while", "switch", "try", "catch", "do"}:
                objects.clear()  # never carry an object through uncertain control flow/scopes
            if token[0] == "id" and i + 1 < len(tokens) and values[i + 1] == "=":
                objects.pop(value, None)
        if token[0] != "id" or (i and values[i - 1] in {".", "?."}):
            continue
        end = i + 1
        chain = value
        while end + 1 < len(tokens) and values[end] == "." and tokens[end + 1][0] == "id":
            chain += "." + values[end + 1]
            end += 2
        if end >= len(tokens) or values[end] != "(" or end not in pairs:
            continue
        if value in blocked:
            continue
        canonical = bindings.get(value, value) + chain[len(value):]
        arguments = token_segments(tokens, pairs, end + 1, pairs[end])
        first = arguments[0] if arguments else None
        name = token_string(tokens, first)
        designator = api_algorithm(name)
        if javascript:
            if canonical.startswith("node:crypto."):
                member = canonical.removeprefix("node:crypto.")
                if member in {"generateKeyPair", "generateKeyPairSync"} and designator and designator[1] in {"migration_review", "pqc_reference", "legacy_pqc_reference"}:
                    options = token_object(tokens, pairs, arguments[1]) if len(arguments) > 1 else None
                    size = token_integer(tokens, options.get("modulusLength")) if options and designator[0] in {"RSA", "DSA"} else None
                    parameters = {}
                    exponent = token_integer(tokens, options.get("publicExponent"), 2_147_483_647) if options and designator[0] == "RSA" else None
                    if exponent is not None:
                        parameters["public_exponent"] = exponent
                    add(i, designator, "node:crypto." + member, operation="key_generation", size=size, parameters=parameters, literal=first)
                elif member in {"generateKey", "generateKeySync"} and name and name.lower() in {"aes", "hmac"}:
                    options = token_object(tokens, pairs, arguments[1]) if len(arguments) > 1 else None
                    size = token_integer(tokens, options.get("length")) if options else None
                    add(i, designator, "node:crypto." + member, operation="key_generation", size=size, literal=first)
                elif member in {"createCipheriv", "createDecipheriv"} and designator and designator[0] == "AES/ChaCha20":
                    add(i, designator, "node:crypto." + member, role="encryption", operation="algorithm_selection", literal=first)
                elif member in {"createHash", "createHmac", "createSign", "createVerify", "sign", "verify"} and designator:
                    allowed = designator[3] == "hashing" if member in {"createHash", "createHmac"} else designator[3] in {"hashing", "signature"}
                    if not allowed:
                        continue
                    role = "hashing" if member == "createHash" else ("authentication" if member == "createHmac" else "signature")
                    operation = {"sign": "signing", "verify": "verification"}.get(member, "algorithm_selection")
                    add(i, designator, "node:crypto." + member, role=role, operation=operation, literal=first)
            web_roots = {"crypto.subtle", "window.crypto.subtle", "globalThis.crypto.subtle", "node:crypto.webcrypto.subtle", "node:crypto.subtle"}
            root, _, member = canonical.rpartition(".")
            if root in web_roots and member in {"generateKey", "sign", "verify", "encrypt", "decrypt", "digest", "deriveBits", "deriveKey"}:
                options = token_object(tokens, pairs, first)
                literal = options.get("name") if options is not None else first
                designator = api_algorithm(token_string(tokens, literal))
                if designator:
                    family, category, variant, hint = designator
                    allowed = {
                        "generateKey": category in {"migration_review", "pqc_reference", "legacy_pqc_reference"} or family in {"AES/ChaCha20", "HMAC"},
                        "sign": hint in {"signature", "authentication"}, "verify": hint in {"signature", "authentication"},
                        "encrypt": hint == "encryption", "decrypt": hint == "encryption", "digest": hint == "hashing",
                        "deriveBits": hint in {"key_agreement", "key_derivation"}, "deriveKey": hint in {"key_agreement", "key_derivation"}}
                    if not allowed[member]:
                        continue
                    operation = {"generateKey": "key_generation", "sign": "signing", "verify": "verification",
                                 "encrypt": "encryption", "decrypt": "decryption", "digest": "hashing",
                                 "deriveBits": "key_derivation", "deriveKey": "key_derivation"}[member]
                    hint = designator[3]
                    role = {"sign": "signature", "verify": "signature", "encrypt": "encryption", "decrypt": "encryption",
                            "digest": "hashing", "deriveBits": "key_derivation", "deriveKey": "key_derivation"}.get(member, hint)
                    if hint == "authentication" and member in {"sign", "verify"}:
                        role = "authentication"
                    if hint == "key_agreement" and member in {"deriveBits", "deriveKey"}:
                        role, operation = "key_agreement", "key_agreement"
                    size = None
                    if member == "generateKey" and options:
                        if designator[0] == "RSA":
                            size = token_integer(tokens, options.get("modulusLength"))
                        elif designator[0] in {"AES/ChaCha20", "HMAC"}:
                            size = token_integer(tokens, options.get("length"))
                    parameters = {}
                    if options and member in {"deriveBits", "deriveKey"}:
                        iterations = token_integer(tokens, options.get("iterations"), 2_147_483_647)
                        if iterations is not None:
                            parameters["iterations"] = iterations
                    add(i, designator, "WebCrypto.subtle." + member, role=role, operation=operation, size=size, parameters=parameters, literal=literal)
        else:
            class_name, _, member = canonical.rpartition(".")
            if class_name in JAVA_CLASSES.values() and member == "getInstance" and designator:
                kind = class_name.rsplit(".", 1)[-1]
                family, category, variant, hint = designator
                allowed = {
                    "KeyPairGenerator": category in {"migration_review", "pqc_reference", "legacy_pqc_reference"},
                    "KeyGenerator": family in {"AES/ChaCha20", "HMAC", "HMAC-SHA-2"},
                    "Cipher": family in {"RSA", "AES/ChaCha20"} and hint in {"unknown", "encryption"},
                    "Signature": hint == "signature" or family == "RSA", "MessageDigest": hint == "hashing",
                    "Mac": hint == "authentication", "KeyAgreement": hint == "key_agreement"}
                if not allowed.get(kind, False):
                    continue
                roles = {"Signature": "signature", "MessageDigest": "hashing", "Cipher": "encryption",
                         "KeyAgreement": "key_agreement", "Mac": "authentication"}
                add(i, designator, canonical, role=roles.get(kind), literal=first)
                # Only an immediately declared local-like variable; no aliases or fields.
                if i >= 3 and values[i - 1] == "=" and tokens[i - 2][0] == "id" and values[i - 3] in {kind, "var"}:
                    objects[values[i - 2]] = (class_name, designator, roles.get(kind, designator[3]), None)
            elif canonical == JAVA_CLASSES["RSAKeyGenParameterSpec"] and i and values[i - 1] == "new":
                add(i, api_algorithm("RSA"), canonical, size=token_integer(tokens, first))
            elif value in objects and chain == value + "." + chain.rsplit(".", 1)[-1]:
                class_name, designator, role, cipher_operation = objects[value]
                member = chain.rsplit(".", 1)[-1]
                kind = class_name.rsplit(".", 1)[-1]
                size, operation = None, None
                if (kind == "KeyPairGenerator" and member == "initialize") or (kind == "KeyGenerator" and member == "init"):
                    operation, size = "algorithm_selection", token_integer(tokens, first)
                elif (kind == "KeyPairGenerator" and member in {"generateKeyPair", "genKeyPair"}) or (kind == "KeyGenerator" and member == "generateKey"):
                    operation = "key_generation"
                elif kind == "Signature" and member in {"sign", "verify", "initSign", "initVerify"}:
                    operation = {"sign": "signing", "verify": "verification"}.get(member, "algorithm_selection")
                elif kind == "MessageDigest" and member == "digest":
                    operation = "hashing"
                elif kind == "KeyAgreement" and member == "generateSecret":
                    operation = "key_agreement"
                elif kind == "Mac" and member == "doFinal":
                    operation = "reference"
                elif kind == "Cipher" and member == "init":
                    mode = "".join(values[first[0]:first[1]]) if first else ""
                    allowed_modes = {JAVA_CLASSES["Cipher"] + ".ENCRYPT_MODE": "encryption", JAVA_CLASSES["Cipher"] + ".DECRYPT_MODE": "decryption"}
                    if mode.startswith("Cipher.") and bindings.get("Cipher") == JAVA_CLASSES["Cipher"]:
                        mode = JAVA_CLASSES["Cipher"] + mode[len("Cipher"):]
                    cipher_operation = allowed_modes.get(mode)
                    objects[value] = (class_name, designator, role, cipher_operation)
                    operation = "algorithm_selection"
                elif kind == "Cipher" and member == "doFinal":
                    operation = cipher_operation or "reference"
                if operation:
                    add(i, designator, class_name + "." + member, role=role, operation=operation, size=size)
    return results, covered


def scan_dependency_source(path, source):
    parsed = pqdeps.parse_manifest(path, source)
    starts = [0] + [match.end() for match in re.finditer("\n", source)]
    results = []
    for record in parsed["records"]:
        offset = record["offset"]
        index = bisect_right(starts, offset) - 1 if offset is not None else 0
        line, column = index + 1, offset - starts[index] + 1 if offset is not None else 1
        metadata = record["dependency"]
        item = finding(path, line, column, metadata["name"], "dependency_review", "dependency_manifest",
                       metadata["ecosystem"] + " [Bibliotheksdeklaration]")
        item["dependency"] = metadata
        item["bsi_review"] = "Aus einer Bibliotheksdeklaration folgt keine Algorithmus-, PQC- oder BSI-Konformitätsbewertung."
        results.append(item)
    return results, parsed["warnings"]


def supported_source(path):
    return Path(path).suffix.lower() in EXTENSIONS or Path(path).name in SOURCE_FILENAMES


def protected_input(path):
    return supported_source(path) or pqdeps.manifest_kind(path) is not None


def mask_php_comments(source):
    """Mask common PHP comments, preserving offsets and non-PHP template text.

    Only long PHP tags and <?= are recognized. This is a text heuristic, not a
    PHP/template lexer; heredoc/nowdoc and embedded languages are not parsed.
    PHP 8 attributes (#[) are preserved. A closing tag ends line comments.
    """
    chars = list(source)
    i, in_php, quote = 0, False, None
    opening = re.compile(r"<\?(?:php(?=\s|$)|=)", re.I)
    while i < len(source):
        if not in_php:
            match = opening.search(source, i)
            if match is None:
                break
            i, in_php = match.end(), True
        elif quote:
            if source[i] == "\\":
                i += 2
                continue
            if source[i] == quote:
                quote = None
            i += 1
        elif source.startswith("?>", i):
            in_php, i = False, i + 2
        elif source[i] in "\"'`":
            quote, i = source[i], i + 1
        elif source.startswith("//", i) or (source[i] == "#" and not source.startswith("#[", i)):
            endings = [p for p in (source.find("\n", i), source.find("?>", i)) if p >= 0]
            end = min(endings) if endings else len(source)
            for k in range(i, end):
                if chars[k] not in "\r\n":
                    chars[k] = " "
            i = end
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = len(source) if end < 0 else end + 2
            for k in range(i, end):
                if chars[k] not in "\r\n":
                    chars[k] = " "
            i = end
        else:
            i += 1
    return "".join(chars)


def scan_source(path, source):
    if pqdeps.manifest_kind(path) is not None:
        return scan_dependency_source(path, source)[0]
    if Path(path).suffix.lower() in {".py", ".pyw"}:
        scanner = PythonScanner(path)
        scanner.visit(ast.parse(source, filename=str(path)))
        return scanner.findings
    results, covered = scan_api_patterns(path, source)
    covered.sort()
    starts = [start for start, end in covered]
    if Path(path).suffix.lower() in PHP_EXTENSIONS:
        source = mask_php_comments(source)
    else:
        ruby = Path(path).suffix.lower() in RUBY_EXTENSIONS or Path(path).name in SOURCE_FILENAMES
        source = mask_comments(source, hash_comments=ruby, c_comments=not ruby)
    offset = 0
    for number, line in enumerate(source.splitlines(keepends=True), 1):
        for algorithm, category, start in token_findings(line):
            absolute = offset + start
            index = bisect_right(starts, absolute) - 1
            if index >= 0 and absolute < covered[index][1]:
                continue
            results.append(finding(path, number, start + 1, algorithm, category,
                                   "text_heuristic", algorithm + " [Textmuster]",
                                   bsi_profile.recognized_variant(line[start:], algorithm)))
        offset += len(line)
    results.sort(key=lambda item: (item["line"], item["column"], item["algorithm"]))
    return results


def excluded(relative, patterns):
    value = relative.as_posix()
    return any(fnmatch.fnmatchcase(value, pat) or fnmatch.fnmatchcase(relative.name, pat)
               for pat in patterns)


def is_link(path):
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def attach_source_context(findings, source):
    """Capture the scanned snapshot, never reread files when exporting a report."""
    lines = source.splitlines()
    cache = {}
    for item in findings:
        number = item["line"]
        if not 1 <= number <= len(lines):
            continue
        focus = max(0, item["column"] - 1)
        if item["method"] == "python_ast":
            focus = len(lines[number - 1].encode("utf-8")[:focus].decode("utf-8", errors="ignore"))
        key = (number, focus if len(lines[number - 1]) > MAX_CONTEXT_LINE_CHARS else 0)
        if key not in cache:
            start, end = max(1, number - SOURCE_CONTEXT_RADIUS), min(len(lines), number + SOURCE_CONTEXT_RADIUS)
            rows = []
            for current in range(start, end + 1):
                text = lines[current - 1]
                left = min(max(0, focus - MAX_CONTEXT_LINE_CHARS // 2), max(0, len(text) - MAX_CONTEXT_LINE_CHARS)) if current == number else 0
                rows.append({"number": current, "text": text[left:left + MAX_CONTEXT_LINE_CHARS],
                             "start_column": left + 1, "truncated": len(text) > MAX_CONTEXT_LINE_CHARS})
            cache[key] = {"start_line": start, "end_line": end, "highlight_line": number, "lines": rows}
        item["source_context"] = cache[key]


def source_context_text(item):
    context = item.get("source_context")
    if not context:
        return "Codekontext nicht enthalten (älterer Bericht oder ausdrücklich deaktiviert)."
    width = len(str(context["end_line"]))
    rows = []
    for row in context["lines"]:
        # Prevent source control characters from changing the terminal display.
        text = "".join(ch if ch == "\t" or ord(ch) >= 32 and ord(ch) != 127 else repr(ch)[1:-1] for ch in row["text"])
        clip = f" [Ausschnitt ab Spalte {row['start_column']}; lange Zeile gekürzt]" if row["truncated"] else ""
        rows.append(("> " if row["number"] == context["highlight_line"] else "  ") + f"{row['number']:>{width}} | " + text + clip)
    return "\n".join(rows)


def source_context_html(item):
    context = item.get("source_context")
    if not context:
        return "<p>Codekontext nicht enthalten.</p>"
    esc = lambda value: html.escape(str(value), quote=True)
    rows = "".join('<span class="source-hit">' + esc(line) + '</span>\n' if line.startswith("> ") else esc(line) + '\n'
                   for line in source_context_text(item).splitlines())
    return f'<details class="source-context" open><summary>Code · Zeilen {context["start_line"]}–{context["end_line"]} (±5)</summary><pre><code>{rows}</code></pre></details>'


def scan_project(target, excludes=(), max_bytes=2_000_000, omit_paths=(), on_progress=None, cancel_event=None, risk_context="unknown", protocol_context="general", python_only=False, scan_dependencies=True, source_context=True):
    if type(source_context) is not bool:
        raise ValueError("source_context muss ein Wahrheitswert sein.")
    if type(scan_dependencies) is not bool:
        raise ValueError("scan_dependencies muss ein Wahrheitswert sein.")
    if type(python_only) is not bool:
        raise ValueError("python_only muss ein Wahrheitswert sein.")
    if max_bytes <= 0:
        raise ValueError("Die maximale Dateigröße muss positiv sein.")
    target = Path(os.path.abspath(target))
    if not target.exists() or is_link(target):
        raise ValueError("Scan-Ziel fehlt oder ist ein symbolischer Link.")
    root = target if target.is_dir() else target.parent
    report = {"schema_version": "1.8", "scanner": "PQ Code Scanner", "version": VERSION,
              "created_utc": datetime.now(timezone.utc).isoformat(), "target": str(target),
              "source_root": str(root),
              "analysis": "static", "limitations": LIMITATIONS,
              "options": {"exclude": list(excludes), "max_bytes": max_bytes,
                          "gitignore_respected": False, "symlinks_followed": False,
                          "language_filter": "python" if python_only else "all",
                          "scan_dependencies": scan_dependencies, "dependency_catalog": pqdeps.CATALOG_VERSION,
                          "source_context": source_context, "source_context_radius": SOURCE_CONTEXT_RADIUS,
                          "max_context_line_chars": MAX_CONTEXT_LINE_CHARS},
              "files_scanned": 0, "analyzed_files": [], "findings": [], "skipped": [], "errors": [], "manifest_warnings": [], "cancelled": False}
    report["policy_profile"] = bsi_profile.profile(risk_context, protocol_context)
    omit_paths = {Path(p).absolute() for p in omit_paths}

    def walk_error(error):
        report["errors"].append({"file": str(error.filename), "reason": str(error)})

    def candidates():
        if target.is_file():
            yield target
            return
        for directory, dirs, files in os.walk(target, followlinks=False, onerror=walk_error):
            kept = []
            for name in sorted(dirs):
                path = Path(directory) / name
                if name in SKIP_DIRS or is_link(path):
                    report["skipped"].append({"file": path.relative_to(root).as_posix(), "reason": "Standardausschluss oder Verknüpfung"})
                elif excluded(path.relative_to(root), excludes):
                    report["skipped"].append({"file": path.relative_to(root).as_posix(), "reason": "Benutzerausschluss"})
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in sorted(files):
                yield Path(directory) / name

    for path in candidates():
        if cancel_event is not None and cancel_event.is_set():
            report["cancelled"] = True
            break
        if path in omit_paths:
            continue
        relative = path.relative_to(root)
        manifest = pqdeps.manifest_kind(path) if scan_dependencies else None
        if not supported_source(path) and manifest is None:
            # Unsupported extensions are counted, without retaining every path.
            report["unsupported_files"] = report.get("unsupported_files", 0) + 1
            continue
        reason = None
        if is_link(path):
            reason = "Symbolischer Link"
        elif excluded(relative, excludes):
            reason = "Benutzerausschluss"
        elif python_only and path.suffix.lower() not in {".py", ".pyw"} and not (manifest and manifest[1] == "pypi"):
            reason = "Sprachfilter: nur Python"
        if reason:
            report["skipped"].append({"file": relative.as_posix(), "reason": reason})
            continue
        if on_progress:
            on_progress(report["files_scanned"], relative.as_posix())
        try:
            # Bounded read also protects against files growing after stat().
            with path.open("rb") as stream:
                raw = stream.read(max_bytes + 1)
            if len(raw) > max_bytes or b"\x00" in raw:
                report["skipped"].append({"file": relative.as_posix(), "reason": "Zu groß oder Binärinhalt"})
                continue
            if path.suffix.lower() in {".py", ".pyw"}:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                source = raw.decode(encoding)
            else:
                source = raw.decode("utf-8-sig")
            if manifest:
                file_findings, warnings = scan_dependency_source(relative.as_posix(), source)
                report["manifest_warnings"].extend({"file": relative.as_posix(), "reason": warning} for warning in warnings)
            else:
                file_findings = scan_source(relative.as_posix(), source)
            if source_context:
                attach_source_context(file_findings, source)
            # Preserve a test/example hint when that directory itself is the scan root.
            for item in file_findings:
                item["context"] = path_context(Path(root.name) / relative)
            report["findings"].extend(file_findings)
            report["files_scanned"] += 1
            report["analyzed_files"].append(relative.as_posix())
        except pqdeps.Unavailable as error:
            report["skipped"].append({"file": relative.as_posix(), "reason": str(error)})
        except (OSError, UnicodeError, SyntaxError, RecursionError, ValueError) as error:
            # SyntaxError.__str__ contains location, but never echo its source line.
            detail = error.msg if isinstance(error, SyntaxError) else str(error)
            report["errors"].append({"file": relative.as_posix(), "reason": type(error).__name__ + ": " + detail})
    if cancel_event is not None and cancel_event.is_set():
        report["cancelled"] = True
    report["findings"].sort(key=lambda item: (item["file"], item["line"], item["column"], item["algorithm"]))
    report["summary"] = dict(Counter(item["category"] for item in report["findings"]))
    report["unsupported_files"] = report.get("unsupported_files", 0)
    return report


def report_styles():
    return """
:root{color-scheme:dark}*{box-sizing:border-box}body{font:16px/1.6 system-ui,sans-serif;background:#101827;color:#e5edf8;margin:0;padding:clamp(16px,4vw,40px)}
main{max-width:1200px;margin:auto;min-width:0}h1{font-size:clamp(28px,4vw,38px);line-height:1.2;margin:12px 0}h2{margin-top:32px}h3,h4,p{margin-top:0}p,li,dd{color:#bccbdf}a{color:#79e2c5}code{overflow-wrap:anywhere}.eyebrow{color:#79e2c5;letter-spacing:.12em;font-size:12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(160px,100%),1fr));gap:12px;margin:24px 0}.card{background:#1c2a40;padding:18px;border:1px solid #304057;border-radius:10px;min-width:0}.card>strong,.card>b{display:block;font-size:30px;color:#fff}
.notice{border-left:3px solid #e5bc6c;padding:12px 16px;background:#202b3b}.findings{display:grid;gap:24px}.finding-card{min-width:0;border:1px solid #304057;border-radius:12px;background:#172337;overflow-wrap:anywhere}.finding-header{padding:20px 24px;border-bottom:1px solid #304057}.finding-header h3{font-size:22px;margin:10px 0}.finding-badges{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.badge{font-size:12px;line-height:1.5;border:1px solid #426079;border-radius:20px;padding:4px 10px;color:#d5e4f5;background:#21334b}.badge-category{border-color:#4b806e;color:#a4efd7}.source-location{font-size:14px;margin:0;color:#c6d4e6}.finding-grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:28px;padding:24px}.finding-grid>section{min-width:0}.finding-grid h4{font-size:16px;color:#79e2c5;margin-bottom:12px}.reason-list{margin:0}.reason-list dt{font-weight:600;color:#e5edf8;margin:16px 0 4px}.reason-list dt:first-child{margin-top:0}.reason-list dd{margin:0}.technical-list{margin:0;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.6fr);gap:10px 14px;font-size:14px}.technical-list dt{color:#a9b8cc}.technical-list dd{margin:0;overflow-wrap:anywhere}.next-step{margin:20px 0 0;border-left:2px solid #79e2c5;padding-left:14px}.policy-details{margin-top:18px;font-size:14px}.policy-details summary{cursor:pointer;color:#a9c9ed}.code-panel{padding:0 24px 24px;min-width:0}.source-context{min-width:0}.source-context summary{cursor:pointer;color:#79e2c5;font-size:14px}.source-context pre{display:block;width:100%;max-width:100%;max-height:440px;overflow:auto;background:#0a1220;padding:16px;border:1px solid #2a3c53;border-radius:8px;white-space:pre;font:13px/1.65 ui-monospace,Consolas,monospace;margin:12px 0 0}.source-context code{overflow-wrap:normal}.source-hit{display:inline-block;min-width:100%;background:#233f37;color:#adf5d8}summary{overflow-wrap:anywhere}.empty{padding:20px;border:1px dashed #40546c;border-radius:8px}
@media(max-width:760px){.finding-grid{grid-template-columns:minmax(0,1fr);gap:24px;padding:18px}.finding-header{padding:18px}.code-panel{padding:0 18px 18px}.technical-list{grid-template-columns:minmax(0,1fr) minmax(0,1.5fr)}}
@media print{:root{color-scheme:light}body{background:#fff;color:#111;padding:0}p,li,dd,.source-location{color:#333}.finding-card,.card,.notice{background:#fff;border-color:#bbb}.finding-grid h4,a,.source-context summary{color:#17634e}.finding-header,.finding-grid,.code-panel{padding:14px}.finding-grid{display:block}.finding-grid>section+section{margin-top:16px}.source-context pre{max-height:none;white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f5f5;color:#111}.source-hit{background:#def4e8;color:#111}.finding-card{break-inside:auto}.badge{color:#222;background:#f1f4f7}.reason-list dt{color:#111}.card>strong,.card>b{color:#111}}
"""


def render_finding_html(item, number=None, language="de", status=None, source_url=None):
    esc = lambda value: html.escape(str(value), quote=True)
    english = language == "en"
    reason = explain_finding(item, "en") if english else (item.get("rationale") or explain_finding(item))
    labels = {"python_ast": "Python AST", "api_heuristic": "API heuristic" if english else "API-Heuristik",
              "text_heuristic": "Text pattern" if english else "Textmuster", "dependency_manifest": "Library declaration" if english else "Bibliotheksdeklaration"}
    category = item["category"] if english else LABELS[item["category"]]
    badges = ('<span class="badge">' + esc(status) + '</span>') if status else ""
    badges += '<span class="badge badge-category">' + esc(category) + '</span><span class="badge">' + esc(labels[item["method"]]) + '</span>'
    position = esc(item["file"]) + ":" + str(item["line"]) + ":" + str(item["column"])
    if source_url and source_url.startswith("https://"):
        position = '<a href="' + esc(source_url + quote(item["file"], safe="/") + '#L' + str(item["line"])) + '">' + position + '</a>'
    if "previous_line" in item:
        position += " · " + ("Previous line: " if english else "Frühere Zeile: ") + str(item["previous_line"])
    prefix = ("Finding " if english else "Fundstelle ") + str(number) + " · " if number is not None else ""
    role = item.get("crypto_role", "unknown")
    operation = item.get("operation", "reference")
    size = str(item["key_size_bits"]) + " Bit" if item.get("key_size_bits") is not None else ("Not captured" if english else "Nicht erfasst")
    fields = [("Purpose" if english else "Zweck", role.replace("_", " ") if english else ROLE_LABELS.get(role, "Einsatzzweck offen")),
              ("Operation" if english else "Vorgang", operation.replace("_", " ") if english else OPERATION_LABELS.get(operation, "API-Verweis")),
              ("Key size" if english else "Schlüsselgröße", size),
              ("Evidence" if english else "Erkanntes Muster / API", item["evidence"])]
    if item.get("parameters"):
        fields.append(("Parameters" if english else "Parameter", ", ".join(f"{key}={value}" for key, value in sorted(item["parameters"].items()))))
    if item.get("dependency"):
        fields.append(("Declaration" if english else "Deklaration", pqdeps.describe(item["dependency"])))
    technical = "".join("<dt>" + esc(key) + "</dt><dd>" + esc(value) + "</dd>" for key, value in fields)
    reason_labels = [("detection", "Why detected" if english else "Warum erkannt?"),
                     ("assessment", "Why this classification" if english else "Warum diese Einordnung?"),
                     ("limitations", "What remains unverified" if english else "Was bleibt ungeprüft?")]
    reasons = "".join("<dt>" + label + "</dt><dd>" + esc(reason[key]) + "</dd>" for key, label in reason_labels)
    policy = '<details class="policy-details"><summary>BSI-Orientierung</summary><p>' + esc(item["bsi_review"]) + '</p></details>' if item.get("bsi_review") else ""
    snippet = source_context_html(item)
    if english:
        snippet = snippet.replace("Codekontext nicht enthalten.", "Source context not included.").replace("Code · Zeilen", "Source code · lines")
    return ('<article class="finding-card"><header class="finding-header"><div class="finding-badges">' + badges + '</div><h3>' + esc(prefix + (item.get("variant") or item["algorithm"])) + '</h3><p class="source-location"><code>' + position + '</code></p></header><div class="finding-grid"><section><h4>' + ("Reasoning" if english else "Begründung") + '</h4><dl class="reason-list">' + reasons + '</dl><p class="next-step">' + ('Next step: ' if english else 'Nächster Schritt: ') + esc(reason["next_step"]) + '</p></section><section><h4>' + ("Captured details" if english else "Erfasste Details") + '</h4><dl class="technical-list">' + technical + '</dl>' + policy + '</section></div><div class="code-panel">' + snippet + '</div></article>')


def render_html(report):
    esc = lambda value: html.escape(str(value), quote=True)
    findings = "".join(render_finding_html(item, index) for index, item in enumerate(report["findings"], 1))
    counts = "".join("<div class='card'><strong>" + str(report["summary"].get(key, 0)) + "</strong>" + esc(label) + "</div>" for key, label in LABELS.items())
    listing = lambda rows, empty: "".join("<li>" + esc(e["file"]) + ": " + esc(e["reason"]) + "</li>" for e in rows) or "<li>" + empty + "</li>"
    errors = listing(report["errors"], "Keine.")
    skipped = listing(report["skipped"], "Keine.")
    warnings = listing(report.get("manifest_warnings", []), "Keine zusätzlichen Hinweise.")
    limits = "".join("<li>" + esc(value) + "</li>" for value in report["limitations"])
    return ('<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>PQ Code Scanner – Bericht</title><style>' + report_styles() + '</style></head><body><main><div class="eyebrow">LOKALE QUELLCODEANALYSE · VERSION ' + esc(VERSION) + '</div><h1>Kryptografie sichtbar machen.</h1><p>Statisches Inventar zur Vorbereitung einer Post-Quanten-Migration.</p><p><b>Ziel:</b> ' + esc(report["target"]) + '<br><b>Zeitpunkt (UTC):</b> ' + esc(report["created_utc"]) + '</p><p>Analysierte Dateien: ' + str(report["files_scanned"]) + ' · Übersprungen: ' + str(len(report["skipped"])) + ' · Nicht unterstützte Dateien: ' + str(report["unsupported_files"]) + ' · Fehler: ' + str(len(report["errors"])) + '</p>' + ('<p class="notice">Abgebrochen: Dieser Bericht enthält nur einen Teilscan.</p>' if report.get("cancelled") else '') + '<p class="notice">Auch ein Bericht ohne Treffer belegt keine Quantensicherheit. PQC-Verweise sind kein Sicherheitsnachweis.</p>' + bsi_profile.render_html(report["policy_profile"]) + '<div class="cards">' + counts + '</div><h2>Fundstellen und Begründungen</h2><div class="findings">' + (findings or '<p class="empty">Keine passenden Fundstellen erkannt.</p>') + '</div><h2>Analysefehler</h2><ul>' + errors + '</ul><details><summary>Übersprungene Pfade</summary><ul>' + skipped + '</ul></details><h2>Hinweise zu Projektdateien</h2><ul>' + warnings + '</ul><h2>Grenzen des Berichts</h2><ul>' + limits + '</ul></main></body></html>')


def to_sarif(report):
    """SARIF 2.1.0. Line locations only: Python stores UTF-8 byte columns."""
    categories = list(LABELS)
    rules = [{"id": "PQSCAN/" + key, "shortDescription": {"text": LABELS[key]},
              "fullDescription": {"text": NOTES[key] + " " + GUIDANCE[key]},
              "defaultConfiguration": {"level": "note"},
              "properties": {"tags": ["cryptography", "static-analysis", key]}} for key in categories]
    root = Path(report["source_root"])
    results = []
    for item in report["findings"]:
        key = item["category"]
        level = "warning" if item["method"] == "python_ast" and key in {"migration_review", "classical_weakness"} else "note"
        results.append({
            "ruleId": "PQSCAN/" + key, "ruleIndex": categories.index(key), "level": level,
            "message": {"text": (item["variant"] or item["algorithm"]) + ": " + details_text(item) + ". Begründung: " + " ".join((item.get("rationale") or explain_finding(item)).values()) + " " + item["bsi_review"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": quote(item["file"], safe="/"), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": item["line"]}}}],
            "properties": {"algorithm": item["algorithm"], "method": item["method"],
                           "context": item["context"], "evidence": item["evidence"], "variant": item["variant"],
                           "advisories": item["advisories"], "parameterReview": item["parameter_review"],
                           "dependency": item.get("dependency"), "rationale": item.get("rationale") or explain_finding(item), **{key: item[key] for key in empty_details()}}})
        if item["advisories"]:
            results[-1]["level"] = "warning"
        context = item.get("source_context")
        if context:
            physical = results[-1]["locations"][0]["physicalLocation"]
            physical["contextRegion"] = {"startLine": context["start_line"], "endLine": context["end_line"],
                "snippet": {"text": "\n".join(row["text"] for row in context["lines"])},
                "properties": {"truncated": any(row["truncated"] for row in context["lines"])}}
            physical["region"]["snippet"] = {"text": next(row["text"] for row in context["lines"] if row["number"] == item["line"])}
            results[-1]["properties"]["sourceContext"] = context
    notifications = [{"level": "error", "message": {"text": e["file"] + ": " + e["reason"]}}
                     for e in report["errors"]]
    notifications.extend({"level": "warning", "message": {"text": e["file"] + ": " + e["reason"]}}
                         for e in report.get("manifest_warnings", []))
    if report.get("cancelled"):
        notifications.append({"level": "warning", "message": {"text": "Scan abgebrochen. Ergebnisse sind unvollständig."}})
    if not report["files_scanned"]:
        notifications.append({"level": "error", "message": {"text": "Keine Datei analysiert."}})
    return {"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0", "runs": [{
                "tool": {"driver": {"name": "PQ Code Scanner", "version": VERSION, "rules": rules}},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": root.absolute().as_uri().rstrip("/") + "/"}},
                "invocations": [{"executionSuccessful": bool(report["files_scanned"]) and not report["errors"] and not report.get("cancelled"),
                                 "toolExecutionNotifications": notifications}],
                "results": results,
                "properties": {"limitations": report["limitations"], "skipped": report["skipped"],
                               "unsupportedFiles": report["unsupported_files"], "options": report["options"],
                               "policyProfile": report["policy_profile"]}}]}


def write_report(report, path, format_name, overwrite=False):
    path = Path(path)
    if protected_input(path) or is_link(path):
        raise ValueError("Berichte dürfen weder Quellcode-/Projektdateien noch symbolische Links überschreiben.")
    if Path(os.path.abspath(path)) == Path(report["target"]):
        raise ValueError("Der Bericht darf das Scan-Ziel nicht überschreiben.")
    if format_name == "html":
        content = render_html(report)
    elif format_name in {"json", "sarif"}:
        content = json.dumps(to_sarif(report) if format_name == "sarif" else report, ensure_ascii=False, indent=2)
    else:
        raise ValueError("Unbekanntes Berichtsformat.")
    with path.open("w" if overwrite else "x", encoding="utf-8") as stream:
        stream.write(content + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Quellcode lokal nach Kryptografie durchsuchen. Kein Upload, keine Codeausführung.")
    parser.add_argument("target", type=Path, help="Projektordner oder einzelne Quelldatei")
    parser.add_argument("--json", dest="json_path", type=Path, help="JSON-Bericht speichern")
    parser.add_argument("--html", dest="html_path", type=Path, help="HTML-Bericht speichern")
    parser.add_argument("--sarif", dest="sarif_path", type=Path, help="SARIF-2.1.0-Bericht für Entwicklungswerkzeuge speichern")
    parser.add_argument("--no-source-context", action="store_true", help="Codeausschnitte ausdrücklich auslassen (Standard: Fundzeile mit ±5 nummerierten Zeilen)")
    parser.add_argument("--risk-context", choices=list(bsi_profile.RISK_LABELS), default="unknown", help="Manuell bewertetes Anwendungsrisiko für die BSI-Planung; Standard unknown")
    parser.add_argument("--protocol-context", choices=list(bsi_profile.PROTOCOL_LABELS), default="general", help="Manuell gewählter Kontext für TR-Hinweise; keine Protokollprüfung")
    parser.add_argument("--no-dependencies", action="store_true", help="Projekt-/Abhängigkeitsdateien auslassen; nur bisherigen Quellcodescan verwenden")
    parser.add_argument("--python-only", action="store_true", help="Nur Python-Quellcode und passende Python-Projektdateien analysieren")
    parser.add_argument("--exclude", action="append", default=[], help="Relatives Glob-Muster; wiederholbar, z.B. 'tests/*'")
    parser.add_argument("--max-file-kb", type=int, default=2000, help="Maximale Dateigröße in dezimalen KB (Standard: 2000)")
    parser.add_argument("--fail-on", choices=["migration", "legacy", "advisory", "dependency", "any"], help="CI-Exitcode 1 bei passenden Befunden bzw. BSI-Prüfhinweisen")
    parser.add_argument("--force", action="store_true", help="Vorhandene Berichtsdateien überschreiben")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    if args.max_file_kb <= 0:
        parser.error("--max-file-kb muss positiv sein.")
    outputs = [Path(os.path.abspath(p)) for p in (args.json_path, args.html_path, args.sarif_path) if p]
    if len(set(outputs)) != len(outputs):
        parser.error("Die Berichte benötigen unterschiedliche Ausgabepfade.")
    for path in outputs:
        if protected_input(path):
            parser.error("Berichte dürfen keine Quellcode- oder Projektdateien überschreiben.")
        if path.is_symlink():
            parser.error("Ausgabe auf symbolische Links ist nicht erlaubt.")
        if path.exists() and not args.force:
            parser.error(f"Ausgabe existiert bereits: {path}. Zum Überschreiben --force verwenden.")
    try:
        report = scan_project(args.target, args.exclude, args.max_file_kb * 1000, outputs, risk_context=args.risk_context, protocol_context=args.protocol_context, python_only=args.python_only, scan_dependencies=not args.no_dependencies, source_context=not args.no_source_context)
        for path, format_name in ((args.json_path, "json"), (args.html_path, "html"), (args.sarif_path, "sarif")):
            if path:
                write_report(report, path, format_name, overwrite=args.force)
    except (ValueError, OSError) as error:
        print(f"Fehler: {error}", file=sys.stderr)
        return 2
    print(f"PQ Code Scanner {VERSION} | {report['files_scanned']} Dateien | {len(report['findings'])} Fundstellen")
    for key, label in LABELS.items():
        print(f"  {label}: {report['summary'].get(key, 0)}")
    for item in report["findings"]:
        display_algorithm = item["variant"] or item["algorithm"]
        print(f"{item['file']}:{item['line']}:{item['column']}  {display_algorithm}  [{item['method']}]  {LABELS[item['category']]}")
        print("  " + details_text(item))
        print("Begründung:\n" + rationale_text(item))
        if item.get("source_context"):
            print(source_context_text(item))
        for advisory_id in item["advisories"]:
            print(f"  {advisory_id}: {item['bsi_review']}")
    print(f"Übersprungen: {len(report['skipped'])}; nicht unterstützt: {report['unsupported_files']}; Fehler: {len(report['errors'])}")
    for warning in report.get("manifest_warnings", []):
        print(f"Projekthinweis: {warning['file']}: {warning['reason']}")
    for error in report["errors"]:
        print(f"Analysefehler: {error['file']}: {error['reason']}", file=sys.stderr)
    print("Keine Treffer sind kein Sicherheitsnachweis. Vollständige Einordnung und Grenzen stehen im Bericht.")
    if report["files_scanned"] == 0 or report["errors"]:
        return 2
    categories = set(report["summary"])
    if args.fail_on == "dependency" and "dependency_review" in categories:
        return 1
    if args.fail_on == "advisory" and any(item["advisories"] for item in report["findings"]):
        return 1
    if args.fail_on == "any" and categories:
        return 1
    if args.fail_on == "migration" and "migration_review" in categories:
        return 1
    if args.fail_on == "legacy" and "classical_weakness" in categories:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
