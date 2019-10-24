# Bindra

Ghidra decompiler integration for Binary Ninja 

**_TODO_**: *Add a more complete description*

## Roadmap:

- [ ] Understand how to send functions' instructions to the decompiler (`getPacked` query) and implement it
- [ ] Parse Ghidra decompiler's output (XML formatted)
- [ ] Add an UI element to Binary Ninja and display the generated code
- [ ] Dynamically create the `getMappedSymbolsXML` query
- [ ] Dynamically create the `getComments` query
- [ ] Dynamically create the `getTrackedRegisters` query
- [ ] Clean the source code
- [ ] Buy a new Binja license and update the code with the new API
- [ ] Manage Ghidra decompiler's options from Binary Ninja (add a new UI element) 
- [ ] Support all Binja architectures (currently only `x86` and `x86_64`). Cf [architectures](__init__.py#L28-L67)

# Contributions

For the moment, many decompiler's queries are hardcoded (cf. [queries](query_handler.py)).  
Feel free, if you know how these work, to open a new issue and explain how it works so I can, then, implement it in Python. You can even, if you have time, fork the project, implement the query and make a pull request.
