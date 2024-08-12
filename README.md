# Block DLL Policy Process Creator

This C++ project demonstrates how to create a new process in Windows with a mitigation policy that blocks non-Microsoft signed DLLs. The code implements a function to launch a process with this security policy and an example program that uses this function.

## Features

- **Create Process with DLL Policy**: Blocks non-Microsoft signed DLLs from being loaded into the created process.
- **Customizable Policy**: The block DLL policy can be enabled or disabled using preprocessor directives.
- **Fork with Policy**: The program can fork itself with the policy applied, ensuring that the child process is protected.

## Getting Started

### Prerequisites

- **Windows OS**: This project is designed for Windows operating systems.
- **Visual Studio**: Recommended IDE for compiling and running the project.
- **Windows SDK**: Required for accessing the necessary Windows API functions.

### Building the Project

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/Raulisr00t/DLLPolicyBlock.git
    cd DLLPolicyBlock/
    ```

2. **Open the Project**:
    - Open the project in Visual Studio.

3. **Build the Project**:
    - Select `Build > Build Solution` in Visual Studio.

### Running the Program

After building the project, you can run the executable from the command line or within Visual Studio.

#### Example Usage

1. **Run With DLL Policy in Local Process**:
    ```bash
    block.exe
    ```
    
2. **Run with DLL Policy in Remote Process**:
    ```bash
    block.exe Raulisr00t
    ```

    This will create a new process with the block DLL policy enabled, preventing non-Microsoft signed DLLs from being loaded into the process.

### Code Structure

- **`CreateProcessWithDllPolicy` Function**:
    - Responsible for creating a process with the specified DLL block policy.
    - Uses `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, and other Windows API functions to set up and apply the policy.

- **Main Program**:
    - Checks the command-line arguments to determine whether to apply the DLL block policy.
    - Uses `GetModuleFileNameA` to retrieve the current executable's path and forks itself with the policy if necessary.

### Error Handling

The program includes error handling for various potential issues, such as:
- Failure to allocate memory.
- Failure to initialize process attributes.
- Failure to create a new process.

If an error occurs, the program outputs a descriptive error message and exits.

### Customization

- **LOCAL_BLOCKDLLPOLICY**: 
    - This preprocessor directive controls whether the block DLL policy is enabled. 
    - You can define or undefine it to toggle the feature.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The project makes extensive use of Windows API functions, particularly those related to process creation and security policies.
- Inspired by techniques for securing Windows processes against DLL injection attacks.

