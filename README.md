# POC-ExFlushTb
A POC for monitoring Tb. This code is not neat, it's just a POC.

![image](https://github.com/backengineering/POC-ExFlushTb/assets/13917777/969792a5-7c6d-4e43-afba-71b56eabd5bc)

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
