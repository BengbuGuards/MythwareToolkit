# Project: MythwareToolkit
#
# Usage (run in cmd, with the matching MinGW bin in PATH):
#   mingw32-make ARCH=x64            -> UIAccess x64 (needs signing)
#   mingw32-make ARCH=x86            -> UIAccess x86 (needs signing)
#   mingw32-make ARCH=x86 portable   -> Portable x86 (no signing)
#
# ARCH defaults to x64. Version comes from include/version.h.
# The .bat scripts are the canonical build path; this Makefile mirrors them.

ARCH     ?= x64

# Read the version without calling an external shell command (works in cmd and sh):
# the only quoted token in version.h is the version string itself.
VERSION := v$(subst ",,$(firstword $(filter "%",$(file <include/version.h))))

CXX      ?= g++
WINDRES  ?= windres
RM       = del /q /f

# Compiler / linker flags
CXXFLAGS   = -O3 -pipe -lntdll -fexec-charset=UTF-8 -Iinclude -DUIACCESS_BUILD
CXXFLAGS_P = -O3 -pipe -lntdll -fexec-charset=UTF-8 -Iinclude
LFLAGS     = -s -mwindows -lcomctl32 -lole32 -loleaut32 -luuid -static
LFLAGS_P   = -s -mwindows -lcomctl32 -lgdi32 -static

# Source files
SRCDIR   = src
CPPS     = $(SRCDIR)/main.cpp $(SRCDIR)/utils.cpp $(SRCDIR)/process.cpp \
           $(SRCDIR)/bypass.cpp $(SRCDIR)/assistant.cpp $(SRCDIR)/mythware.cpp \
           $(SRCDIR)/hooks.cpp $(SRCDIR)/psd.cpp $(SRCDIR)/ui.cpp $(SRCDIR)/floating.cpp

# Object / output paths (separate directories per arch and per variant)
OUTDIR   = bin
OBJDIR   = $(OUTDIR)/obj_$(ARCH)
OBJDIR_P = $(OUTDIR)/objp_$(ARCH)
OBJS     = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(CPPS))
OBJS_P   = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR_P)/%.o,$(CPPS))
RES      = $(OBJDIR)/resource.res
RES_P    = $(OBJDIR_P)/resource.res
BIN      = $(OUTDIR)/MythwareToolkit.$(VERSION).$(ARCH).exe
BIN_P    = $(OUTDIR)/MythwareToolkit.$(VERSION).$(ARCH).Portable.exe

.PHONY: all portable clean _build_portable

# ---- Default: UIAccess build ----
all: $(BIN)

$(BIN): $(OBJS) $(RES)
	$(CXX) $(OBJS) $(RES) -o $@ $(LFLAGS)

# ---- Portable build ----
portable: res/sys.manifest
	copy /Y res\sys_portable.manifest res\sys.manifest >nul
	$(MAKE) ARCH=$(ARCH) CXXFLAGS="$(CXXFLAGS_P)" _build_portable
	copy /Y res\sys_original.manifest res\sys.manifest >nul

_build_portable: $(OBJS_P) $(RES_P)
	$(CXX) $(OBJS_P) $(RES_P) -o $(BIN_P) $(LFLAGS_P)

# ---- Resource compilation ----
$(RES): res/resource.rc res/sys.manifest res/app.ico res/float.ico \
        res/MeltdownDFC.exe res/crdisk.exe include/version.h
	@if not exist $(subst /,\,$(OBJDIR)) mkdir $(subst /,\,$(OBJDIR))
	$(WINDRES) -i res/resource.rc --input-format=rc -o $@ -O coff -I include

$(RES_P): res/resource.rc res/sys.manifest res/app.ico res/float.ico \
          res/MeltdownDFC.exe res/crdisk.exe include/version.h
	@if not exist $(subst /,\,$(OBJDIR_P)) mkdir $(subst /,\,$(OBJDIR_P))
	$(WINDRES) -i res/resource.rc --input-format=rc -o $@ -O coff -I include

# ---- Source compilation ----
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp include/globals.h include/version.h
	@if not exist $(subst /,\,$(OBJDIR)) mkdir $(subst /,\,$(OBJDIR))
	$(CXX) -c $< -o $@ $(CXXFLAGS)

$(OBJDIR_P)/%.o: $(SRCDIR)/%.cpp include/globals.h include/version.h
	@if not exist $(subst /,\,$(OBJDIR_P)) mkdir $(subst /,\,$(OBJDIR_P))
	$(CXX) -c $< -o $@ $(CXXFLAGS_P)

# ---- Clean ----
clean:
	-rmdir /s /q $(subst /,\,$(OBJDIR)) >NUL 2>&1
	-rmdir /s /q $(subst /,\,$(OBJDIR_P)) >NUL 2>&1
	-$(RM) $(subst /,\,$(OUTDIR))\*.res >NUL 2>&1
	-$(RM) $(subst /,\,$(OUTDIR))\MythwareToolkit.*.exe >NUL 2>&1
