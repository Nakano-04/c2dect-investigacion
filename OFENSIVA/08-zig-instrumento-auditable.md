# 08 - Zig como instrumento auditable (no como ocultacion)

## Resultado medido

Se implemento la misma funcion de huella en dos lenguajes:

- `footprint.py` (referencia legible)
- `src/footprint.zig` -> `footprint_zig` (nativo, estatico)

Sobre el mismo `fixtures/eventos.json`, ambos producen el MISMO SHA256:

```
ee8a29ebf0c5500a6f2c003da1a6c0fb812295845425c393d137d8cad52fe997
```

Esto es evidencia directa de que **el lenguaje de implementacion no cambia la
huella conductual**. La huella es una propiedad de los eventos observados
(`event_type` + `technica`), no del compilador. Migar un medidor a Zig no lo
vuelve indetectable: vuelve *reproducible*.

## Por que Zig conviene para la investigacion auditable

1. **Binario estatico, sin runtime oculto.** No hay interprete ni GC que
   introduzcan eventos de sistema imprevisibles. La telemetria que genera el
   propio medidor es minima y constante.
2. **Determinismo.** Con version y semilla fijadas, `repro_zig` produce un
   `build_id` estable. Otro revisor compila y obtiene el mismo identificador.
3. **Doble implementacion.** Python + Zig que coinciden en resultados es una
   validacion cruzada del contrato, no una simple reescritura.
4. **Bajo nivel sin dependencias.** Permite escribir correlacion, bootstrap y
   attestation con control explicito de memoria y de E/S, util para instrumentar
   sensores (P3) sin anadir ruido.

## Lo que Zig NO aporta segun esta medicion

- No vuelve "desconocida" la huella: el EDR mira comportamiento, no compilador.
- No cambia el hecho de que un binario Zig minoritario es una senal estadistica
  *mas* rara, no menos.
- No sustituye al sensor: `correlate_zig` solo aplica la regla P3
  (`param_poison -> peb_rx -> thread_hijack`) a eventos ya capturados.

## Herramientas incluidas

| Ejecutable | Funcion | Auditable porque |
|---|---|---|
| `footprint_zig` | Hash canonico de eventos | Coincide con Python, semilla fija |
| `correlate_zig` | Cadena P3 en ventana temporal | Veredicto `caught/landed` con ventana declarada |
| `repro_zig` | `build_id` version + semilla + fuentes | Hash reproducible de las fuentes |
| `bypass_audit_zig` | 1 - recall del sensor | Sensor declarado, n e IC95% |
| `opsec_zig` | Observabilidad por tecnica | Pesos y sensores declarados |
| `verify_manifest_zig` | Integridad del contenido | 32 archivos con SHA256 |

## Conclusion

La ampliacion en Zig mejora la **calidad de la evidencia**, no el sigilo. Es la
diferencia entre "confia en este resultado" y "recompila, verifica el hash y
repite la medicion". Eso es lo que da peso citabled a la investigacion.
