"""
Module 1: Preprocessing & Feature Extraction.
Statically extracts 54 features from raw PE files and defines the dataset preprocessing pipeline.
"""

import math
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
import pefile
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon Entropy of a byte stream.
    Ranges from 0.0 (no randomness) to 8.0 (completely random / compressed / encrypted).
    """
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def get_resources(pe: pefile.PE) -> List[Tuple[int, bytes]]:
    """
    Recursively traverse the resource directory to extract sizes and raw byte contents of resources.
    """
    resources: List[Tuple[int, bytes]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return resources

    def walk_directory(directory: Any) -> None:
        for entry in directory.entries:
            if entry.is_directory:
                walk_directory(entry.directory)
            else:
                data_rva = entry.data.struct.OffsetToData
                size = entry.data.struct.Size
                try:
                    data = pe.get_data(data_rva, size)
                    resources.append((size, data))
                except Exception:
                    # Ignore read errors for malformed or truncated resources
                    pass

    walk_directory(pe.DIRECTORY_ENTRY_RESOURCE)
    return resources


def get_version_info_size(pe: pefile.PE) -> int:
    """
    Extract the size of the version information resource block (RT_VERSION, ID 16).
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return 0
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == 16:  # RT_VERSION

            def sum_leaf_sizes(directory: Any) -> int:
                size_sum = 0
                for sub_entry in directory.entries:
                    if sub_entry.is_directory:
                        size_sum += sum_leaf_sizes(sub_entry.directory)
                    else:
                        size_sum += sub_entry.data.struct.Size
                return size_sum

            if entry.is_directory:
                return sum_leaf_sizes(entry.directory)
    return 0


def extract_pe_features(file_bytes: bytes) -> Dict[str, Any]:
    """
    Extract 54 static features from a raw PE file byte stream matching the CSV dataset schema.
    """
    pe = pefile.PE(data=file_bytes)

    # 1. COFF File Header Features
    machine = pe.FILE_HEADER.Machine
    size_of_optional_header = pe.FILE_HEADER.SizeOfOptionalHeader
    characteristics = pe.FILE_HEADER.Characteristics

    # 2. Optional Header Features
    major_linker_version = pe.OPTIONAL_HEADER.MajorLinkerVersion
    minor_linker_version = pe.OPTIONAL_HEADER.MinorLinkerVersion
    size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
    size_of_initialized_data = pe.OPTIONAL_HEADER.SizeOfInitializedData
    size_of_uninitialized_data = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    address_of_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    base_of_code = pe.OPTIONAL_HEADER.BaseOfCode

    # BaseOfData is only present in 32-bit PE files, not 64-bit
    base_of_data = getattr(pe.OPTIONAL_HEADER, "BaseOfData", 0)

    image_base = pe.OPTIONAL_HEADER.ImageBase
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    major_os_version = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    minor_os_version = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    major_image_version = pe.OPTIONAL_HEADER.MajorImageVersion
    minor_image_version = pe.OPTIONAL_HEADER.MinorImageVersion
    major_subsystem_version = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    minor_subsystem_version = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    checksum = pe.OPTIONAL_HEADER.CheckSum
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    size_of_stack_reserve = pe.OPTIONAL_HEADER.SizeOfStackReserve
    size_of_stack_commit = pe.OPTIONAL_HEADER.SizeOfStackCommit
    size_of_heap_reserve = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    size_of_heap_commit = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    loader_flags = pe.OPTIONAL_HEADER.LoaderFlags
    number_of_rva_and_sizes = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # 3. PE Sections Statistics
    sections_nb = len(pe.sections)
    sections_entropies = []
    sections_raw_sizes = []
    sections_virtual_sizes = []

    for section in pe.sections:
        # Calculate entropy on raw section data
        sec_data = section.get_data()
        sections_entropies.append(calculate_entropy(sec_data))
        sections_raw_sizes.append(section.SizeOfRawData)
        sections_virtual_sizes.append(section.Misc_VirtualSize)

    if sections_entropies:
        sections_mean_entropy = float(np.mean(sections_entropies))
        sections_min_entropy = float(np.min(sections_entropies))
        sections_max_entropy = float(np.max(sections_entropies))
    else:
        sections_mean_entropy = sections_min_entropy = sections_max_entropy = 0.0

    if sections_raw_sizes:
        sections_mean_rawsize = float(np.mean(sections_raw_sizes))
        sections_min_rawsize = float(np.min(sections_raw_sizes))
        section_max_rawsize = float(np.max(sections_raw_sizes))
    else:
        sections_mean_rawsize = sections_min_rawsize = section_max_rawsize = 0.0

    if sections_virtual_sizes:
        sections_mean_virtualsize = float(np.mean(sections_virtual_sizes))
        sections_min_virtualsize = float(np.min(sections_virtual_sizes))
        section_max_virtualsize = float(np.max(sections_virtual_sizes))
    else:
        sections_mean_virtualsize = sections_min_virtualsize = section_max_virtualsize = 0.0

    # 4. Imports and Dynamic Linking
    imports_nb_dll = 0
    imports_nb = 0
    imports_nb_ordinal = 0

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        imports_nb_dll = len(pe.DIRECTORY_ENTRY_IMPORT)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                imports_nb += 1
                if imp.name is None:
                    imports_nb_ordinal += 1

    # 5. Exports
    export_nb = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        export_nb = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

    # 6. Resources Statistics
    resources = get_resources(pe)
    resources_nb = len(resources)
    resources_entropies = []
    resources_sizes = []

    for size, res_data in resources:
        resources_entropies.append(calculate_entropy(res_data))
        resources_sizes.append(size)

    if resources_entropies:
        resources_mean_entropy = float(np.mean(resources_entropies))
        resources_min_entropy = float(np.min(resources_entropies))
        resources_max_entropy = float(np.max(resources_entropies))
    else:
        resources_mean_entropy = resources_min_entropy = resources_max_entropy = 0.0

    if resources_sizes:
        resources_mean_size = float(np.mean(resources_sizes))
        resources_min_size = float(np.min(resources_sizes))
        resources_max_size = float(np.max(resources_sizes))
    else:
        resources_mean_size = resources_min_size = resources_max_size = 0.0

    # 7. Additional Directories
    load_configuration_size = 0
    if (
        len(pe.DIRECTORY_ENTRY_ACTIVE_CONFIG)
        > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]
    ):
        load_config_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]
        ]
        load_configuration_size = load_config_dir.Size

    version_information_size = get_version_info_size(pe)

    # Return ordered dictionary representing exactly the 54 features used by the model
    return {
        "Machine": machine,
        "SizeOfOptionalHeader": size_of_optional_header,
        "Characteristics": characteristics,
        "MajorLinkerVersion": major_linker_version,
        "MinorLinkerVersion": minor_linker_version,
        "SizeOfCode": size_of_code,
        "SizeOfInitializedData": size_of_initialized_data,
        "SizeOfUninitializedData": size_of_uninitialized_data,
        "AddressOfEntryPoint": address_of_entry_point,
        "BaseOfCode": base_of_code,
        "BaseOfData": base_of_data,
        "ImageBase": image_base,
        "SectionAlignment": section_alignment,
        "FileAlignment": file_alignment,
        "MajorOperatingSystemVersion": major_os_version,
        "MinorOperatingSystemVersion": minor_os_version,
        "MajorImageVersion": major_image_version,
        "MinorImageVersion": minor_image_version,
        "MajorSubsystemVersion": major_subsystem_version,
        "MinorSubsystemVersion": minor_subsystem_version,
        "SizeOfImage": size_of_image,
        "SizeOfHeaders": size_of_headers,
        "CheckSum": checksum,
        "Subsystem": subsystem,
        "DllCharacteristics": dll_characteristics,
        "SizeOfStackReserve": size_of_stack_reserve,
        "SizeOfStackCommit": size_of_stack_commit,
        "SizeOfHeapReserve": size_of_heap_reserve,
        "SizeOfHeapCommit": size_of_heap_commit,
        "LoaderFlags": loader_flags,
        "NumberOfRvaAndSizes": number_of_rva_and_sizes,
        "SectionsNb": sections_nb,
        "SectionsMeanEntropy": sections_mean_entropy,
        "SectionsMinEntropy": sections_min_entropy,
        "SectionsMaxEntropy": sections_max_entropy,
        "SectionsMeanRawsize": sections_mean_rawsize,
        "SectionsMinRawsize": sections_min_rawsize,
        "SectionMaxRawsize": section_max_rawsize,
        "SectionsMeanVirtualsize": sections_mean_virtualsize,
        "SectionsMinVirtualsize": sections_min_virtualsize,
        "SectionMaxVirtualsize": section_max_virtualsize,
        "ImportsNbDLL": imports_nb_dll,
        "ImportsNb": imports_nb,
        "ImportsNbOrdinal": imports_nb_ordinal,
        "ExportNb": export_nb,
        "ResourcesNb": resources_nb,
        "ResourcesMeanEntropy": resources_mean_entropy,
        "ResourcesMinEntropy": resources_min_entropy,
        "ResourcesMaxEntropy": resources_max_entropy,
        "ResourcesMeanSize": resources_mean_size,
        "ResourcesMinSize": resources_min_size,
        "ResourcesMaxSize": resources_max_size,
        "LoadConfigurationSize": load_configuration_size,
        "VersionInformationSize": version_information_size,
    }


def preprocess_dataset(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Clean the raw input DataFrame by removing identifier fields,
    resolving duplicate/contradictory records, and splitting into features (X) and label (y).
    """
    # 1. Resolve duplicate and contradictory records (duplicate md5 with conflicting labels)
    if "md5" in df.columns and "legitimate" in df.columns:
        # Identify hashes that have more than one unique label value
        grouped = df.groupby("md5")["legitimate"].nunique()
        contradictory_hashes = grouped[grouped > 1].index

        # Remove contradictory rows entirely to prevent model confusion
        df = df[~df["md5"].isin(contradictory_hashes)]

        # Remove perfect duplicate rows based on hash
        df = df.drop_duplicates(subset=["md5"])

    # 2. Extract target label ('legitimate' column: 1 = benign, 0 = malware)
    if "legitimate" not in df.columns:
        raise ValueError("Dataset must contain target column 'legitimate'")

    y = df["legitimate"]

    # 3. Extract feature matrix X (drop metadata and target columns)
    cols_to_drop = ["Name", "md5", "legitimate"]
    cols_to_drop = [c for c in cols_to_drop if c in df.columns]
    X = df.drop(columns=cols_to_drop)

    return X, y


def get_preprocessor_pipeline(X: pd.DataFrame) -> ColumnTransformer:
    """
    Build and return a ColumnTransformer pipeline that handles missing values,
    encoding of categorical columns, and normalization of numeric columns.
    """
    # Identify numeric and categorical columns dynamically
    numeric_features = X.select_dtypes(include=[np.number]).columns.tolist()
    categorical_features = X.select_dtypes(exclude=[np.number]).columns.tolist()

    # Numeric Pipeline: Median Imputation + StandardScaler
    numeric_transformer = Pipeline(
        steps=[("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler())]
    )

    # Categorical Pipeline: Most Frequent Imputation + OneHotEncoder
    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ]
    )

    # Combined Preprocessor using ColumnTransformer
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_features),
            ("cat", categorical_transformer, categorical_features),
        ],
        remainder="drop",
    )

    # Enable returning pandas DataFrames for downstream model tracking
    preprocessor.set_output(transform="pandas")

    return preprocessor
