# to load the data
install.packages("jsonlite")
library("jsonlite")

# For frequency counting
install.packages("plyr")
library("plyr")


# data import
CVE16 <- fromJSON("nvdcve-1.0-2016.json")
View(CVE16)

