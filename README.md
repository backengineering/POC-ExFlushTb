# POC-ExFlushTb
A POC for monitoring Tb.

## Principle
Hijack ``HalIommuDispatch + 0x48``
![image](https://github.com/backengineering/POC-ExFlushTb/assets/13917777/e4ac4eb9-0b0d-450a-ae19-76854264dfcf)
```
KeFlushSingleTb
    -> ExFlushTb
KeFlushTb
    -> ExFlushTb
```

## Compile
- Visual Studio 2022 & WDK10
- llvm-msvc [[link]](https://github.com/backengineering/llvm-msvc/releases)
