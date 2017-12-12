@@@@@@@    @@@@@@@   @@@@@@   @@@@@@@    @@@@@@    @@@@@@@   @@@@@@   @@@  @@@
@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@
@@!  @@@  !@@       @@!  @@@  @@!  @@@  !@@       !@@       @@!  @@@  @@!@!@@@
!@!  @!@  !@!       !@!  @!@  !@!  @!@  !@!       !@!       !@!  @!@  !@!!@!@!
@!@@!@!   !@!       @!@!@!@!  @!@@!@!   !!@@!!    !@!       @!@!@!@!  @!@ !!@!
!!@!!!    !!!       !!!@!!!!  !!@!!!     !!@!!!   !!!       !!!@!!!!  !@!  !!!
!!:       :!!       !!:  !!!  !!:            !:!  :!!       !!:  !!!  !!:  !!!
:!:       :!:       :!:  !:!  :!:           !:!   :!:       :!:  !:!  :!:  !:!
 ::        ::: :::  ::   :::   ::       :::: ::    ::: :::  ::   :::   ::   ::
 :         :: :: :   :   : :   :        :: : :     :: :: :   :   : :  ::    :



PCAPscan analyzes a large amount of pcap files by extracting interesting
information

Requirements
============

* python3
* make
* see requirements.txt

Installation
============

There is a make file that helps installing the necessary packets in a
python environment:

```
% make install
```

For more dev utilities see

```
% make help
```

Analyzers
=========

A central aspect of pcapscan are analyzers. Each analyzer gets a packet
instance and performs its analysis by storing relevant information in
a [synchronized data structure](https://docs.python.org/3/library/multiprocessing.html#managers).
After analyzing all packets, the collected information are written as
csv file to allow further investigation.


LICENSE
=========

* GPLv3
* for details see LICENSE
