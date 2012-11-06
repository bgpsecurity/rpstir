data <- read.table('run-times-over-time.dat')
data$Start <- as.POSIXlt(read.table('times.dat')$Start)

png('run-times-over-time.png')
plot(data)
dev.off()
