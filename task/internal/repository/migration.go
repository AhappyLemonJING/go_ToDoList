package repository

import "fmt"

func migration() {
	err := DB.Set("gorm:table_options", "charset=utf8mb4").AutoMigrate(
		&Task{},
	)
	if err != nil {
		fmt.Println("migration err", err)
	}
}
