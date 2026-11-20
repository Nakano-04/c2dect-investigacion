# Capa ofensiva — marco de investigación

Esta carpeta amplifica la dimensión ofensiva de C2-DECT como **objeto de
estudio**, no como armamento. Todo el material es análisis, metodología y
medición; no contiene implementaciones de evasión, inyección, persistencia ni
otras capacidades operativas.

> Alcance: laboratorio aislado, alcance declarado y RoE firmada. Uso exclusivo
> autorizado. Ver `PLANES_INVESTIGACION_4-7.md`.

## Principio rector

La tesis del proyecto es que la capacidad ofensiva sólo aporta valor cuando es
**verificable**. Por eso la pregunta de investigación no es «¿cómo evado más?»,
sino «¿qué huella observable deja cada técnica y cómo se mide?». Un artefacto
que no puede medirse no entra en el catálogo como «real».

## Documentos

| # | Documento | Qué aporta |
|---|---|---|
| 01 | `modelo-de-amenaza.md` | Activos, adversario, supuestos y superficie de ataque del escenario emulado |
| 02 | `matriz-attck-cobertura.md` | Mapa de técnicas, cobertura de detección y brechas |
| 03 | `cadena-de-ataque.md` | Las 7 fases, sus puntos de observación y sus criterios de verdad |
| 04 | `resistencia-deteccion-metodo.md` | Metodología para medir la detectabilidad como propiedad |
| 05 | `opsec-como-metrica.md` | La huella operativa cuantificada (prototipo `opsec_score.py`) |
| 06 | `hipotesis-brechas.md` | Hipótesis falsables sobre brechas de detección |

## Prototipo verificable

`opsec_score.py` calcula una **puntuación de observabilidad** por técnica a
partir de los sensores que la ven (proceso, red, memoria, registro, archivos).
Es una herramienta de **priorización defensiva**: qué técnicas dejan más
rastro y dónde conviene invertir detección. No es una herramienta para elegir
técnicas «sigilosas».

```powershell
python -m unittest discover -v
python opsec_score.py fixtures/tecnicas.json --markdown
```

## Límite explícito

Los repositorios públicos no incluyen código de evasión de AV/EDR, parcheo de
ETW/AMSI, inyección de procesos, bypass de UAC ni mechanical de robo de
credenciales. Esa capacidad se estudia aquí a nivel de **contrato, huella y
detección**, que es la parte publicable y verificable.
