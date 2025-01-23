# CyberLLM

Code and dataset repository for the paper:
> CyberLLM: A new dataset for analysing safety of fine-tuned LLMs using cyber security data

This repository contains all code, dataset, and materials used in the paper.

## Repository Structure

* `dataset/`: The CyberLLM dataset files
  - Contains the main dataset file: `CyberLLM_full_dataset.csv`

* `dataset_creation/`: Dataset creation pipeline
  - Eight sequential scripts (`1_data_collector.py` through `8_final_assembler.py`) for collecting, processing, and validating cyber security data
  - See [`dataset_creation/README.md`](dataset_creation/README.md) for detailed pipeline documentation

* `evaluation/`
  - `cybermetric/`
  - `deepeval/`

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

The following large language models have been fine-tuned on the CyberLLM dataset:
- Llama 3.1 8B
- Mistral 7B
- Llama 2 70B
- Qwen 2.5 Coder 7B
- Gemma 2 9B
- Llama 3 8B
- Phi 3 Mini Instruct 3.8B

## Getting Started

1. Clone the repository:
```bash
git clone https://github.com/adelsamir01/CyberLLM.git
cd CyberLLM
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Follow the specific documentation in each directory for:
- Dataset creation: See `dataset_creation/README.md`
- Fine-tuning models: See `finetune/README.md`
- Model evaluation: See `evaluation/README.md`
- Utility scripts: See `scripts/README.md`
