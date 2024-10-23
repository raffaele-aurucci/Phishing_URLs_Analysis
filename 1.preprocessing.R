# PRE-PROCESSING REAL DATASET
# Author: Raffaele Aurucci

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


# ------------------------------------------------------------------------------
# ATTRIBUTE 'label'

# 0 -> phishing URL
# 1 -> legitimate URL

table(df$label)

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

barplot(tld_filtered$Freq, names.arg = tld_filtered$Var1, col = 'lightblue',
        main = 'Istogramma TLD',
        ylab = 'Frequenza', xlab = 'TLD')

# the most frequent TLD category is .com
filtered_df <- df[df$TLD %in% tld_filtered$Var1, ]
label_counts <- table(filtered_df$TLD, filtered_df$label)
label_counts

plot(label_counts, col = c('orange', 'lightblue'), 
     main = 'Tabella di contingenza TLD',
     ylab = 'Label', xlab = 'TLD')

# TODO: study in deep

# ------------------------------------------------------------------------------
# ATTRIBUTE 'URLLenght'