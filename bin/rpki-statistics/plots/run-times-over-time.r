data <- read.table('run-times-over-time.dat', sep="\t", header=TRUE)
data$Start <- as.POSIXlt(read.table('times.dat', sep="\t", header=TRUE)$Start)

png('run-times-over-time.png', width=1600, height=1200, pointsize=24)
plot(data$Start, data$Duration/60, type="o",
    main="Combined Fetch and Validation Times",
    xlab="Start Time",
    ylab="Time to Fetch and Validate (minutes)")
dev.off()
