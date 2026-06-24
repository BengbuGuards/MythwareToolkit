# Project: MythwareToolkit
# Build: make          → UIAccess build (needs signing)
#        make portable → Portable build (no signing, no install)

CXX      = g++
WINDRES  = windres
RM       = del /q /f

# Compiler / linker flags
CXXFLAGS = -O3 -pipe -lntdll -fexec-charset=UTF-8 -Iinclude
LFLAGS   = -s -mwindows -lcomctl32 -lole32 -loleaut32 -luuid -static
LFLAGS_P = -s -mwindows -lcomctl32 -lgdi32 -lgdiplus -lole32 -static

# Source files
SRCDIR   = src
CPPS     = $(SRCDIR)/main.cpp $(SRCDIR)/utils.cpp $(SRCDIR)/process.cpp \
           $(SRCDIR)/bypass.cpp $(SRCDIR)/assistant.cpp $(SRCDIR)/mythware.cpp \
           $(SRCDIR)/hooks.cpp $(SRCDIR)/psd.cpp $(SRCDIR)/floating.cpp

# Object files
OUTDIR   = bin
OBJS     = $(patsubst $(SRCDIR)/%.cpp,$(OUTDIR)/%.o,$(CPPS))
RES      = $(OUTDIR)/resource.res
BIN      = $(OUTDIR)/MythwareToolkit.exe
BIN_P    = $(OUTDIR)/MythwareToolkit_Portable.exe

.PHONY: all portable clean

# ── Default: UIAccess build ─────────────────────────────────
all: $(BIN)

$(BIN): $(OBJS) $(RES)
	$(CXX) $(OBJS) $(RES) -o $@ $(LFLAGS)

# ── Portable build ──────────────────────────────────────────
portable: res/sys.manifest
	copy /Y res\sys_portable.manifest res\sys.manifest >nul
	$(MAKE) BIN=$(BIN_P) LFLAGS="$(LFLAGS_P)" _build_portable
	copy /Y res\sys_original.manifest res\sys.manifest >nul

_build_portable: $(OBJS) $(RES)
	$(CXX) $(OBJS) $(RES) -o $(BIN_P) $(LFLAGS_P)

# ── Resource compilation ────────────────────────────────────
$(RES): res/resource.rc res/sys.manifest res/app.ico \
        res/floating.jpg res/MeltdownDFC.exe res/crdisk.exe
	$(WINDRES) -i res/resource.rc --input-format=rc -o $@ -O coff

# ── Source compilation ──────────────────────────────────────
$(OUTDIR)/%.o: $(SRCDIR)/%.cpp include/globals.h
	@if not exist $(OUTDIR) mkdir $(OUTDIR)
	$(CXX) -c $< -o $@ $(CXXFLAGS)

# ── Clean ───────────────────────────────────────────────────
clean:
	-$(RM) $(subst /,\,$(OUTDIR))\*.o >NUL 2>&1
	-$(RM) $(subst /,\,$(OUTDIR))\*.res >NUL 2>&1
	-$(RM) $(subst /,\,$(OUTDIR))\MythwareToolkit*.exe >NUL 2>&1
