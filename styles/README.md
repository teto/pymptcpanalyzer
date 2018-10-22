Contains matplotlib styles. To be able to use them for your plot, copy them
(you can make available for your user in `$XDG_CONFIG_HOME/matplotlib/stylelib`)
or use the fullpath

See https://matplotlib.org/users/customizing.html#the-matplotlibrc-file for an exhaustive list of parameters.


figure.autolayout will adapt the size of the figure but might put suptitle across the frame.

One of the most important parameters is `axes.prop_cycle    : cycler(color='bgrcmyk')` as it allows to set the representation of the lines.

`mptcpanalyzer iperf-client-linux_linux_1nbRtrs_f30b30_f30b30_w10K_lia_roundrobin-run0.pcap "plot dsn 0 --style presentation"`


My style changes are not taken into account ?

Matplotlib loads styles once at the beginning so you need to restart mptcpanalyzer.

