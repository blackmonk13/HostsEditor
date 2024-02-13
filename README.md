# Hosts Editor

## Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)
- [Todo](#todo)
- [Contributing](#contributing)

## About <a name = "about"></a>

Hosts Editor is a PowerShell script designed to simplify the management of the `hosts` file on a Windows system. It provides an interactive interface for adding, removing, enabling, and disabling entries, backing up and restoring the `hosts` file, and displaying its content in a table format.

## Getting Started <a name = "getting_started"></a>

### Prerequisites

Ensure that you have PowerShell installed on your Windows system.

### Installing

1. Clone the repository to your local machine.
2. Navigate to the directory containing the script.
3. Run the script with administrative privileges.

## Usage <a name = "usage"></a>

After launching the script, you will be presented with a menu to choose the operation you wish to perform. Follow the prompts to manage your `hosts` file.

## Todo <a name = "todo"></a>

- **Logging**: Implement logging to track script execution and changes made to the `hosts` file.
- **Read Entries from File**: Add functionality to read entries from a separate file instead of manually entering them during runtime.
- **Configuration File**: Create a configuration file to store script preferences and settings. This file can be in JSON, XML, or another format.
- **Registry Access**: Enhance the script to read and write configurations to the Windows Registry, providing a centralized storage location for settings.

## Contributing <a name = "contributing"></a>

Contributions are welcome!
