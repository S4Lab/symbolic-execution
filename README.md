# SymbolicExecution

This repository contains an implementation of the forward symbolic execution based on the LDMBL API.
Less Duplication, More Business Logic (LDMBL) is a Pin-based architecture which provides flexible and abstract API for heavy weight dynamic binary instrumentation use cases. A sample use case is the forward symbolic execution which requires instrumenting all assembly instructions to track the specific logics of each instruction symbolically.
This repo is a subproject of the Twinner automatic deobfuscation framework.

## Installation

Use make files.

## Usage

Run the SE pintool as follows for the usage details:

    pin -t ./obj-intel64/SE.so -h -- echo test

## License
    Copyright © 2013-2018 Behnam Momeni

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see {http://www.gnu.org/licenses/}.
