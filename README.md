# CrashLogger for GTA V

CrashLogger is a lightweight debugging helper for GTA V mods.  
It detects engine-level crashes and lets your C# mods write their own log entries, making it much easier to track down issues during development.  
Supports both **GTA V Legacy** and **GTA V Enhanced**.

---

## Features
- Detects silent or normal engine crashes  
- Lets your mod write custom log messages  
- Outputs detailed information to **CrashLogger_Log.txt**  
- Simple integration via a single C# file  

---

## Requirements
- **ScriptHookV**

---

## Installation
1. Drop `CrashLogger.dll` into your main **GTA V directory**.

---

## Integration (for mod developers)
1. In your mod project, create a new script file.  
2. Copy the contents of **Integration.cs** into that file.  
3. Change its namespace to match your project.  
4. Call the logger from any script using:
   - `YourNamespace.Log("Overloaded");`
   - `YourNamespace.Log(ex, "Located in Main.cs");`

After a crash, open your GTA V directory and check **CrashLogger_Log.txt** for all logged info.

---

## Why use CrashLogger?
Tired of silent crashes or your own crash handler not giving answers?  
CrashLogger provides engine-crash's error codes and custom logs.

