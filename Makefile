# Project: MythwareToolkit

CXX      = "g++.exe"
CC       = "gcc.exe"
WINDRES  = "windres.exe"
RM       = del /q /f
CD       = cd /d
LIBS     = "-s" "-mwindows" "C:/Windows/System32/Comctl32.dll" "C:/Windows/System32/FltLib.dll" "-static"
INCS     = 
CXXINCS  = 
CXXFLAGS = $(CXXINCS) "-O3" "-pipe" "-lntdll"
CFLAGS   = $(INCS) "-O2" "-pipe"
WINDRESFLAGS = 
RES      = resource.res
OBJ      = main.o $(RES)
BIN      = MythwareToolkit.exe
LINKOBJ  = "bin/main.o" "bin/resource.res"
CLEANOBJ = "bin/main.o" "bin/resource.res" "bin/MythwareToolkit.exe"

.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	-$(RM) $(CLEANOBJ) >NUL 2>&1

MythwareToolkit.exe: $(OBJ)
	$(CXX) $(LINKOBJ) -o "bin/MythwareToolkit.exe" $(LIBS)

main.o: main.cpp
	$(CXX) -c "main.cpp" -o "bin/main.o"$(CXXFLAGS)

resource.res: resource.rc
	$(WINDRES) -i "resource.rc" --input-format=rc -o "bin/resource.res" -O coff $(WINDRESFLAGS) 
