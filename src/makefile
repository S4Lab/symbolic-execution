
all: se.base se.base.gil se.base.gil.gar

se.base:
	make -f se.makefile se.base

se.base.gil:
	make -f se.makefile se.base.gil

se.base.gil.gar:
	make -f se.makefile se.base.gil.gar

clean:
	bash -c "rm -rf {obj-ia32,obj-intel64}/{edu,Trace.*,Concolic.*,SE.*}"

.PHONY: all se.base se.base.gil se.base.gil.gar clean
