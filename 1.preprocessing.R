# PRE-PROCESSING REAL DATASET
# Author: Raffaele Aurucci

# install.packages("moments")

library(moments)
library(utils)

df <- read.csv('./datasets/Phishing_URL_Dataset_3.csv', sep = ";")

View(df)

# ------------------------------------------------------------------------------
#                               PRE-PROCESSING

# RQ1: What characteristics of the observed phenomenon provide the greatest 
# discriminatory information for identifying phishing sites compared to 
# legitimate ones?
# ------------------------------------------------------------------------------


# count NA values
labels = names(df)

for (label in labels) {
  na_count <- sum(is.na(df[[label]]))
  print(paste(label, ":", na_count))
}

# delete duplicated observations
df <- df[!duplicated(df), ]

# reset indices
row.names(df) <- NULL

# moda function
moda <- function(x) {
  ux <- unique(x)
  ux[which.max(tabulate(match(x, ux)))]
}

# ------------------------------------------------------------------------------
# ATTRIBUTE 'label'

# 0 -> phishing URL
# 1 -> legitimate URL

table(df$label)

df_0 <- df[df$label == 0, ]
df_1 <- df[df$label == 1, ]

# ------------------------------------------------------------------------------
# ATTRIBUTE 'FILENAME' 

# delete attribute
df <- subset(df, select = -FILENAME)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'URL'

# delete duplicated observations
df <- df[!duplicated(df$URL), ]

# delete attribute because have only unique value
# df <- subset(df, select = -URL)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'Domain'

# delete attribute because have only unique value
df <- subset(df, select = -Domain)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'TLD'

tld_table <- table(df$TLD)

tld_df <- as.data.frame(tld_table)
tld_filtered <- tld_df[tld_df$Freq >= 100, ]

# the most frequent TLD category is 'com'
tld_max = moda(df$TLD)
tld_max

filtered_df <- df[df$TLD %in% tld_filtered$Var1, ]
label_counts <- prop.table(table(filtered_df$label, filtered_df$TLD))
label_counts

barplot(label_counts, col = c('orange', 'lightblue'), 
     main = 'Frequenza relativa congiunta TLD',
     legend = c('phishing', 'legitimate'))

# TODO: study in deep

# ------------------------------------------------------------------------------
# ATTRIBUTE 'URLLenght'

summary(df$URLLength)

breaks <- c(0, 10, 20, 30, 40, 50, 1000) 

j_freq <- table(df$label, cut(df$URLLength, breaks = breaks))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta URLLenght")

# OUTLIERS
summary(df_0$URLLength)
summary(df_1$URLLength)

boxplot(df_0$URLLength, df_1$URLLength, 
        ylim = c(min(df_0$URLLength), quantile(df_0$URLLength, 0.95)),
        main = 'Boxplot URLLenght', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))


# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$URLLength, 0.75) - quantile(df_0$URLLength, 0.25)
M1_0 <- quantile(df_0$URLLength, 0.5) - 1.57*IQR_0/sqrt(length(df_0$URLLength))
M2_0 <- quantile(df_0$URLLength, 0.5) + 1.57*IQR_0/sqrt(length(df_0$URLLength))

IQR_1 <- quantile(df_1$URLLength, 0.75) - quantile(df_1$URLLength, 0.25)
M1_1 <- quantile(df_1$URLLength, 0.5) - 1.57*IQR_1/sqrt(length(df_1$URLLength))
M2_1 <- quantile(df_1$URLLength, 0.5) + 1.57*IQR_1/sqrt(length(df_1$URLLength))

# no overlap: the median is different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)


# DISPERSION
var(df$URLLength)
sd(df$URLLength)


# DISTRIBUTION FORM
skw_value <- skewness(df$URLLength)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$URLLength)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$URLLength)
h_sturges <- (max(df$URLLength) - min(df$URLLength)) / sqrt(n)
density_sturges <- density(df$URLLength, bw = h_sturges)

plot(density_sturges, main = "Distribuzione URLLength", 
     col = "orange", lwd = 2, xlab = 'URLLength')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)


# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$URLLength)
kurtosis_value_0 <- kurtosis(df_0$URLLength)

skw_value_1 <- skewness(df_1$URLLength)
kurtosis_value_1 <- kurtosis(df_1$URLLength)

# calculate sturges bandwidth for dataset phishing (outliers)
n_0 <- length(df_0$URLLength)
h_sturges_0 <- (max(df_0$URLLength) - min(df_0$URLLength)) / sqrt(n_0)
density_sturges_0 <- density(df_0$URLLength, bw = h_sturges_0)

density_1 <- density(df_1$URLLength)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_sturges_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "URLLength", ylab = "Density",
     ylim = c(0, max(density_sturges_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "URLLength", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# ------------------------------------------------------------------------------
# ATTRIBUTE 'DomainLenght'

summary(df$DomainLength)

breaks <- c(0, 10, 20, 30, 40, 50, 100) 

j_freq <- table(df$label, cut(df$DomainLength, breaks = breaks))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta DomainLength")

# OUTLIERS
summary(df_0$DomainLength)
summary(df_1$DomainLength)

boxplot(df_0$DomainLength, df_1$DomainLength,
        main = 'Boxplot DomainLength', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))


# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$DomainLength, 0.75) - quantile(df_0$DomainLength, 0.25)
M1_0 <- quantile(df_0$DomainLength, 0.5) - 1.57*IQR_0/sqrt(length(df_0$DomainLength))
M2_0 <- quantile(df_0$DomainLength, 0.5) + 1.57*IQR_0/sqrt(length(df_0$DomainLength))

IQR_1 <- quantile(df_1$DomainLength, 0.75) - quantile(df_1$DomainLength, 0.25)
M1_1 <- quantile(df_1$DomainLength, 0.5) - 1.57*IQR_1/sqrt(length(df_1$DomainLength))
M2_1 <- quantile(df_1$DomainLength, 0.5) + 1.57*IQR_1/sqrt(length(df_1$DomainLength))

# no overlap: the median is different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)


# DISPERSION
var(df$DomainLength)
sd(df$DomainLength)


# DISTRIBUTION FORM
skw_value <- skewness(df$DomainLength)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$DomainLength)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$DomainLength)
h_sturges <- (max(df$DomainLength) - min(df$DomainLength)) / sqrt(n)
density_sturges <- density(df$DomainLength, bw = h_sturges)

plot(density_sturges, main = "Distribuzione DomainLength", 
     col = "orange", lwd = 2, xlab = 'DomainLenght')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)


# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$DomainLength)
kurtosis_value_0 <- kurtosis(df_0$DomainLength)

skw_value_1 <- skewness(df_1$DomainLength)
kurtosis_value_1 <- kurtosis(df_1$DomainLength)

density_0 <- density(df_0$DomainLength)
density_1 <- density(df_1$DomainLength)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density(df_0$DomainLength), main = "phishing",
     col = "orange", lwd = 2, xlab = "DomainLength", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "DomainLength", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))
# ------------------------------------------------------------------------------
# ATTRIBUTE 'IsDomainIP'

table(df$IsDomainIP)

# delete attribute because have only 81 value setting to 1
df <- subset(df, select = -IsDomainIP)
# ------------------------------------------------------------------------------
# ATTRIBUTE 'URLSimilarityIndex'

summary(df_0$URLSimilarityIndex)
summary(df_1$URLSimilarityIndex)

breaks <- c(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100) 

j_freq <- table(df$label, cut(df$URLSimilarityIndex, breaks = breaks))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta URLSimilarityIndex")

# correlations
