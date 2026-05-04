// Package identity generates plausible Russian display names so our
// goloom peers blend into a real Telemost call participant list instead
// of obviously sticking out as "goloom-server" / "goloom-client".
//
// Adapted from the tun project's proxy-build/identity.go (same author).
package identity

import (
	"fmt"
	"math/rand"
)

var firstNames = []string{
	"Александр", "Дмитрий", "Максим", "Сергей", "Андрей", "Алексей", "Артём", "Илья",
	"Кирилл", "Михаил", "Никита", "Матвей", "Роман", "Егор", "Арсений", "Иван",
	"Денис", "Даниил", "Тимофей", "Владислав", "Игорь", "Павел", "Руслан", "Марк",
	"Анна", "Мария", "Елена", "Дарья", "Анастасия", "Екатерина", "Виктория", "Ольга",
	"Наталья", "Юлия", "Татьяна", "Светлана", "Ирина", "Ксения", "Алина", "Елизавета",
}

var lastNames = []string{
	"Иванов", "Смирнов", "Кузнецов", "Попов", "Васильев", "Петров", "Соколов", "Михайлов",
	"Новиков", "Федоров", "Морозов", "Волков", "Алексеев", "Лебедев", "Семенов", "Егоров",
	"Павлов", "Козлов", "Степанов", "Николаев", "Орлов", "Андреев", "Макаров", "Никитин",
	"Захаров", "Зайцев", "Соловьев", "Борисов", "Яковлев", "Григорьев", "Романов", "Воробьев",
}

// femaleFirstNameIndex marks the start of female first names in the
// firstNames slice — used to apply -а suffix on the last name for women.
const femaleFirstNameIndex = 24

// GenerateName returns a random plausible Russian name. With ~30%
// probability returns just a first name (matches Telemost participant
// patterns where many users put only a first name), otherwise full
// "first last" with proper feminine suffix on the surname when needed.
func GenerateName() string {
	idx := rand.Intn(len(firstNames))
	first := firstNames[idx]

	if rand.Float32() < 0.3 {
		return first
	}

	last := lastNames[rand.Intn(len(lastNames))]
	if idx >= femaleFirstNameIndex {
		return fmt.Sprintf("%s %sа", first, last)
	}
	return fmt.Sprintf("%s %s", first, last)
}

// NameOrGenerate returns name unchanged if non-empty, otherwise a fresh
// random one. Convenient for "use config value or pick something" sites.
func NameOrGenerate(name string) string {
	if name != "" {
		return name
	}
	return GenerateName()
}
