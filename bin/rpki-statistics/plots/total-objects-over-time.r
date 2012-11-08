data <- read.table('total-objects-over-time.dat', sep="\t", header=TRUE)
data$Start <- as.POSIXlt(read.table('times.dat', sep="\t", header=TRUE)$Start)

x <- data$Start
y <- data$CACerts + data$CRLs + data$ROAs + data$MFTs

png('total-objects-over-time.png', width=1600, height=1200, pointsize=24)
plot(x, y, type="0",
    main="Total Number of Objects",
    xlab="Start Time (UTC)",
    ylab="Number of Objects",
    ylim=c(0,max(y)))
dev.off()
