# MTK-Carbonara-Tool

A Python-based utility specialized in implementing the **Carbonara exploit** for MediaTek (MTK) devices. This tool facilitates loading Download Agents (DA), applying specific security bypass patches to the DA binary in memory, and executing privileged DA commands via the XFlash protocol.

While the core architecture is designed to be extensible for various MTK chipsets, it is currently **tested and verified on MT6833 Honor devices**.

## Features

- **Carbonara Exploit Implementation**: Built-in patching engine to dynamically disable security checks (SBC, DAA, Auth, Hash Binding) within the DA2 binary.
- **Extensible Patching**: Supports specific patch profiles (e.g., `mt6833_honor`) and generic ones (`mtkclient`), allowing adaptation for other chipsets that are vulnerable to Carbonara.
- **DA Lifecycle Management**: Handles the full handshake and loading process for Stage 1 (DA1) and Stage 2 (DA2).
- **Custom DA Commands**: Includes `dacmd` for interacting with the specific DA implementation (Memory R/W, Info, etc.).
- **Raw I/O**: Tools for debug and analysis (`raw_tx`, `raw_rx`).

## Requirements

- Python 3.x
- `pyserial`

Install dependencies:
```bash
pip install pyserial
```

## Usage

### Loading Download Agent (DA) with Exploit

To load the DA files and apply the Carbonara patches, use the `load_da` command.

**Example: MT6833 Honor Devices**
This device requires a specific patch (`mt6833_honor`) to handle the legacy binding window and security checks.

```bash
python mtktool.py load_da -1 MT6833_Preloader_DA1.bin -2 MT6833_Preloader_DA2.bin --patch mt6833_honor
```

**Options:**
- `-1`: Path to DA1 binary.
- `-2`: Path to DA2 binary.
- `--patch`: Exploit/Patch mode.
    - `mt6833_honor`: Specific patch for MT6833 Honor devices.
    - `mtkclient`: Generic Carbonara patch (based on bkerler's mtkclient implementation).
    - `none`: Load DA without patching.
- `-d`: Enable debug logging.

### DA Commands (`dacmd`)

Once the DA is loaded and the exploit is active, you can use `dacmd` to execute privileged commands.

**Note:** The `dacmd` command set is tailored to the specific DA implementation included in this toolchain.

**Examples:**

Get Chip ID:
```bash
python mtktool.py dacmd get_chip_id
```

Read RAM Info:
```bash
python mtktool.py dacmd get_ram_info
```

Download Data (Streaming):
```bash
python mtktool.py dacmd download [64B-header-hex] @data.bin
```

Get Help / List Commands:
```bash
python mtktool.py dacmd -h
```

### Preloader Commands

Interact with the device in Preloader mode (before DA is loaded).

```bash
python mtktool.py cmd hwcode
python mtktool.py cmd meid
python mtktool.py cmd socid
```

## Credits & References

This tool integrates knowledge and resources from several projects:

*   **MT6833 HONOR DA Files**: Sourced from [https://gitee.com/geekflashtool/package_mtk_edl](https://gitee.com/geekflashtool/package_mtk_edl).
*   **MTK Communication Protocol**: Reference implementation from [https://github.com/bkerler/mtkclient](https://github.com/bkerler/mtkclient).
*   **Carbonara Exploit**: General exploit details from [https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara).
*   **MT6833 HONOR Carbonara Exploit**: Specific implementation details for MT6833 Honor devices referenced from [GeekFlashTool](https://gitee.com/geekflashtool).

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.
A copy of the license is available in the [LICENSE](LICENSE) file.
