</$objtype/mkfile

BIN=$home/bin/$objtype

TARG=\
	check \
	dec \
	enc \
	gen \
	sign \


PROGS=${TARG:%=%.go}

%.go:
	go build $stem.go

all:V: $PROGS

clean:V:
	rm -f $TARG

nuke:V:
	rm -rf $BIN/pgp

install:V:	all
	mkdir -p $BIN/pgp
	cp $TARG $BIN/pgp/
