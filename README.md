# IDAHelper

IDAHelper is a Python package that provides a set of tools to assist with reverse engineering tasks in IDA Pro.

## Example usage

```python
from idahelper import cpp, memory, tif

pure_virtual_ea = memory.ea_from_name("___cxa_pure_virtual")
for cls, vtable_ea in cpp.get_all_cpp_classes():
    parent_cls = tif.get_parent_class(cls)
```