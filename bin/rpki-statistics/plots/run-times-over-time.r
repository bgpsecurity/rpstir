data <- read.table('run-times-over-time.dat', sep="\t", header=TRUE)
data$Start <- as.POSIXlt(read.table('times.dat', sep="\t", header=TRUE)$Start)

png('run-times-over-time.png')
plot(data)
dev.off()
