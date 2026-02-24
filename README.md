# CyberLLMInstruct

## Citation

If you use this dataset in your research, please cite our paper:

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

This repository contains all code and materials to reproduce the dataset used in the paper. Due to copyright considerations, we provide scripts to regenerate the dataset rather than distributing it directly.

## Repository Structure

* `dataset_creation/`: Dataset creation pipeline
  - Seven sequential scripts (`1_data_collector.py` through `6_security_aligner.py`, and `8_final_assembler.py`) for collecting, processing, and validating cyber security data
  - See [`dataset_creation/README.md`](dataset_creation/README.md) for detailed pipeline documentation
  - Use these scripts to reproduce the dataset following our methodology

* `examples/`: Examples of using the CyberLLMInstruct dataset
  - `deepeval/`: Example 1
  - `cybermetric/`: Example 2
  - `adversarial_prompts/`: Example adversarial prompts from the dataset

* `finetune/`: Comprehensive fine-tuning pipeline
  - `data_prep.py`: Data preprocessing for various LLM architectures
  - `train.py`: Training script with support for LoRA and quantisation
  - `inference.py`: Inference script with interactive and batch modes
  - `checkpoint_manager.py`: Checkpoint management utilities
  - See [`finetune/README.md`](finetune/README.md) for detailed fine-tuning documentation
  
* `scripts/`: Utility scripts for dataset management
  - `categorise.py`: Pattern-based domain categorisation
  - `dataset_export.py`: Dataset export and platform upload
  - See [`scripts/README.md`](scripts/README.md) for usage instructions

## Supported Models

The following large language models have been fine-tuned on the CyberLLMInstruct dataset:
- Phi 3 Mini 3.8B
- Mistral 7B
- Qwen 2.5 7B
- Llama 3 8B
- Llama 3.1 8B
- Gemma 2 9B
- Llama 2 70B


## Getting Started

1. Clone the repository:
```bash
git clone https://github.com/anonymised/CyberLLMInstruct.git
cd CyberLLMInstruct
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install and configure Ollama:
```bash
# Install Ollama (macOS/Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Pull required models
ollama pull gemma:2b
ollama pull mistral:7b
```

4. Dataset Creation:
   To create the dataset, follow the pipeline in the `dataset_creation/` directory:
   - Each script (1-6, 8) should be run sequentially
   - Detailed instructions are provided in `dataset_creation/README.md`
   - This process ensures compliance with data usage rights and allows you to reproduce the dataset
   - The pipeline will create several output directories (raw_data, filtered_data, etc.) as it processes the data

5. Follow the specific documentation in each directory for:
   - Fine-tuning models: See `finetune/README.md`
   - Model evaluation: See `evaluation/README.md`
   - Utility scripts: See `scripts/README.md`

## Generated Directories

The pipeline will create the following directories as it runs:
- `raw_data/`: Initial collected data
- `filtered_data/`: Data after filtering
- `structured_data/`: Structured and cleaned data
- `domain_classified/`: Data after domain classification
- `reviewed_data/`: Data after manual review
- `security_aligned/`: Security-aligned instruction pairs
- `final_dataset/`: Final processed dataset
