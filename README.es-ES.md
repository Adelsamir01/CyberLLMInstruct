

# CyberLLMInstruct

## Citación

Si utiliza este conjunto de datos en su investigación, por favor cite nuestro artículo:

```bibtex
@inproceedings{CyberLLMInstruct,
author = {ElZemity, Adel and Arief, Budi and Li, Shujun},
title = {CyberLLMInstruct: A Pseudo-Malicious Dataset Revealing Safety-Performance Trade-offs in Cyber Security LLM Fine-tuning},
year = {2026},
isbn = {9798400718953},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3733799.3762968},
doi = {10.1145/3733799.3762968},
booktitle = {Proceedings of the 18th ACM Workshop on Artificial Intelligence and Security},
pages = {77–88},
numpages = {12},
series = {AISec '25}
}
```

Este repositorio contiene todo el código y los materiales necesarios para reproducir el conjunto de datos utilizado en el artículo. Debido a consideraciones de derechos de autor, proporcionamos scripts para regenerar el conjunto de datos en lugar de distribuirlo directamente.

## Estructura del repositorio

* `dataset_creation/`: Pipeline de creación del conjunto de datos
  - Siete scripts secuenciales (`1_data_collector.py` a `6_security_aligner.py`, y `8_final_assembler.py`) para recopilar, procesar y validar datos de ciberseguridad
  - Consulte [`dataset_creation/README.md`](dataset_creation/README.md) para ver la documentación detallada del pipeline
  - Utilice estos scripts para reproducir el conjunto de datos siguiendo nuestra metodología

* `examples/`: Ejemplos de uso del conjunto de datos CyberLLMInstruct
  - `deepeval/`: Ejemplo 1
  - `cybermetric/`: Ejemplo 2
  - `adversarial_prompts/`: Prompts adversariales de ejemplo del conjunto de datos

* `finetune/`: Pipeline integral de ajuste fino (fine-tuning)
  - `data_prep.py`: Preprocesamiento de datos para diversas arquitecturas de LLM
  - `train.py`: Script de entrenamiento con soporte para LoRA y cuantización
  - `inference.py`: Script de inferencia con modos interactivos y por lotes
  - `checkpoint_manager.py`: Utilidades de gestión de puntos de control (checkpoints)
  - Consulte [`finetune/README.md`](finetune/README.md) para ver la documentación detallada de ajuste fino
  
* `scripts/`: Scripts de utilidad para la gestión del conjunto de datos
  - `categorise.py`: Categorización de dominios basada en patrones
  - `dataset_export.py`: Exportación del conjunto de datos y carga en plataformas
  - Consulte [`scripts/README.md`](scripts/README.md) para ver las instrucciones de uso

## Modelos compatibles

Los siguientes modelos de lenguaje grandes (LLM) han sido ajustados en el conjunto de datos CyberLLMInstruct:
- Phi 3 Mini 3.8B
- Mistral 7B
- Qwen 2.5 7B
- Llama 3 8B
- Llama 3.1 8B
- Gemma 2 9B
- Llama 2 70B


## Primeros pasos

1. Clone el repositorio:
```bash
git clone https://github.com/anonymised/CyberLLMInstruct.git
cd CyberLLMInstruct
```

2. Instale las dependencias:
```bash
pip install -r requirements.txt
```

3. Instale y configure Ollama:
```bash
# Install Ollama (macOS/Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Pull required models
ollama pull gemma:2b
ollama pull mistral:7b
```

4. Creación del conjunto de datos:
   Para crear el conjunto de datos, siga el pipeline en el directorio `dataset_creation/`:
   - Cada script (1-6, 8) debe ejecutarse secuencialmente
   - Las instrucciones detalladas se encuentran en `dataset_creation/README.md`
   - Este proceso garantiza el cumplimiento de los derechos de uso de los datos y le permite reproducir el conjunto de datos
   - El pipeline creará varios directorios de salida (raw_data, filtered_data, etc.) a medida que procesa los datos

5. Siga la documentación específica en cada directorio para:
   - Ajuste fino de modelos: Consulte `finetune/README.md`
   - Evaluación de modelos: Consulte `evaluation/README.md`
   - Scripts de utilidad: Consulte `scripts/README.md`

## Directorios generados

El pipeline creará los siguientes directorios a medida que se ejecute:
- `raw_data/`: Datos recopilados inicialmente
- `filtered_data/`: Datos después del filtrado
- `structured_data/`: Datos estructurados y limpios
- `domain_classified/`: Datos después de la clasificación por dominio
- `reviewed_data/`: Datos después de la revisión manual
- `security_aligned/`: Pares de instrucciones alineados con la seguridad
- `final_dataset/`: Conjunto de datos procesado final
