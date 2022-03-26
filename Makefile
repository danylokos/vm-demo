CC=clang

define build
	${CC} -o ${1} ${1}.c
	codesign -s "${IDENTITY}" --entitlements ${1}-ents.xml ${1}
endef

demo: demo.c
	$(call build,demo)

runner: runner.c
	$(call build,runner)

.PHONY: all clean

all: clean demo runner

clean:
	rm -f demo runner
