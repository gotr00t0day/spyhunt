# Contributing to SpyHunt

Thank you for considering contributing to SpyHunt! This guide will help you understand the structure of the refactored project and how to contribute new features, especially now that SpyHunt is no longer a monolithic script.

---

## 🧠 Project Architecture

SpyHunt is now modular, organized into the following components:

- `core/arguments.py`: Defines all CLI arguments, grouped by themes.
- `core/groups/`: Contains implementation files for each argument group.
- `core/features/`: Contains feature modules for specific arguments inside a group.

The main file (`spyhunt.py`) is responsible for:
1. Printing the banner.
2. Parsing the arguments.
3. Determining which group(s) of arguments are active.
4. Executing the corresponding module's `run(args)` method based on that group.

---

## ⚙️ Argument Execution Flow

Arguments are categorized by thematic groups, each defined in `core/arguments.py`.

**Execution Order in `spyhunt.py`:**
1. Options (ungrouped arguments)
2. Update
3. Thematic groups (e.g., Passive Recon, Vulnerability, etc.)

The dictionary `group_files` in `spyhunt.py` tracks each group's file and whether it's activated based on CLI arguments.

```python
group_files = {
    "Options": {"file": "options", "active": False},
    ...
}
```

---

## ➕ Adding a New Argument

### Case 1: Belongs to a New Thematic Group

1. **Edit `core/arguments.py`**:
   - Create a new group.
   - Add your argument(s) to it.

2. **Create a file in `core/groups/`**:
   - File name must be lowercase, words separated by `_`.
   - Must match the group title. (e.g., `Hard Recon` → `hard_recon.py`)

3. **Implement `run(args)` function** in that group file.

4. **Add entry to `group_files`** in `spyhunt.py`:
   ```python
   "Hard Recon": {"file": "hard_recon", "active": False}
   ```

5. **Add logic in your group file**:
   - For each argument, write an `if args.argument:` block.
   - If your block requires internal methods, create them inside `core/features/` using the argument name as filename.
     - Example: `args.attack` → `core/features/attack.py`

---

### Case 2: Belongs to an Existing Group

1. **Edit `core/arguments.py`** to add the new argument under the desired group.
2. **Edit the corresponding group file in `core/groups/`** to implement the argument logic.
3. If needed, create additional methods in `core/features/`.

---

### Case 3: Standalone Argument (No Thematic Group)

1. **Edit `core/arguments.py`** to define it without a group.
2. **Implement logic in `core/groups/options.py`**.

---

## 🧪 Example Scenario

Suppose you're adding a new group: `Hard Recon`.

- Add it in `core/arguments.py`:
  ```python
  hard_group = parser.add_argument_group("Hard Recon")
  hard_group.add_argument("--attack", action="store_true", help="Enable attack mode")
  ```

- Create `core/groups/hard_recon.py`:
  ```python
  def run(args):
      if args.attack:
          from core.features import attack
          attack.execute()
  ```

- Create `core/features/attack.py`:
  ```python
  def execute():
      print("Running hard attack...")
  ```

- Update `spyhunt.py`:
  ```python
  "Hard Recon": {"file": "hard_recon", "active": False}
  ```

---

## 🧼 Final Notes

- Ensure new modules don’t break the CLI.
- Follow naming conventions for files and arguments.
- Test each module independently before integrating.

Happy hacking!

— The SpyHunt Team
