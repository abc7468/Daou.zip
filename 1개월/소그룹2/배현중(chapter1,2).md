# 함수형 인터페이스

# 함수형 인터페이스란?

- 단 하나의 추상 메서드만 선언된 인터페이스(default나 static 메서드는 제한없음)

```java
// 예시
@FunctionalInterface  // Annotation을 붙이지 않아도 되지만, 붙이면 함수형 인터페이스인지 검증을 해줌
interface MyFunction {
	public abstract int max(int a, int b);
}
```

- 위의 함수형 인터페이스 구현해보자

```java
MyFunction f = new MyFunction() {
					public int max(int a, int b) { // 익명 클래스(클래스의 선언과 객체의 생성을 동시에)
						return a > b ? a : b;
					}
};
```

- 구현한 max 함수는 이런 식으로 쓸 수 있다

```java
int value = f.max(1, 3); // MyFunction에 max()가 있으므로 사용가능
```

- 함수형 인터페이스 타입의 참조 변수로 람다식을 참조할 수 있음. (단, 함수형 인터페이스의 메서드와 람다식의 매개변수의 개수와 리턴타입이 일치해야 함)

```java
// 람다식(익명 객체)을 다루기 위한 참조변수의 타입은 함수형 인터페이스로 한다.
MyFunction f = (a, b) -> a > b ? a : b; // 람다식. 익명 객체

int value = f.max(1, 3); // 실제로는 람다식(익명 함수)가 호출됨
```

<aside>
💡 함수형 인터페이스는 람다식 활용을 위해 사용된다!!
MyFunction f에 람다식으로만 정의해줬는데, 어떻게 f.max()의 함수를 알아내서 사용할 수 있을까라는 생각이 들었다.
근데 간과하고 있던 점이 바로, 함수형 인터페이스는 **단 하나만의** 추상 메서드가 선언된 인터페이스라는 점!
즉, 람다식으로 정의한다 하더라도 추상 메서드가 하나뿐이기 때문에, 그 메서드의 구현체가 되는 것이다!

</aside>

# 함수형 인터페이스 타입의 매개변수, 반환 타입

- 함수형 인터페이스 타입의 매개변수

```java
@FunctionalInterface
interface MyFunction {
	void myMethod();
}
```

```java
void aMethod(MyFunction f) {
	f.myMethod(); // MyFunction에 정의된 메서드 호출
}
```

```java
MyFunction f = () -> System.out.println("myMethod 호출!");
aMethod(f);
```

```java
// 위의 두 줄을 합치면?!
aMethod(() -> System.out.println("myMethod 호출!"));
```

- 함수형 인터페이스 타입의 리턴타입

```java
MyFunction myMethod() { // 람다식 반환
	MyFunction f = () -> {}; // 람다식
	return f;
}
```

```java
// 위의 두 줄을 합치면
MyFunction myMethod() {
	return () -> {};
}
```

<br>
<br>

# Predicate

자바에서 Predicate는 함수형 인터페이스(Functional Interface) 중 하나로, 주어진 인자값을 받아서 true 또는 false를 반환하는 함수를 의미합니다. 즉, Predicate는 주어진 조건을 만족하는지 여부를 결정하는 함수입니다.

Predicate는 다음과 같이 정의됩니다.

```java
@FunctionalInterface
public interface Predicate<T> {
    boolean test(T t);
}
```

test() 메서드는 제네릭 타입 T의 인자를 받아서 boolean 값을 반환합니다. Predicate를 사용할 때는, 람다 표현식을 활용하여 주어진 조건을 만족하는지 여부를 확인할 수 있습니다. 예를 들어, 다음은 자바 8에서 제공하는 Predicate를 사용하여 문자열이 "Hello"인지 확인하는 예시입니다.

```java
Predicate<String> isHello = str -> "Hello".equals(str);

if (isHello.test("Hello")) {
    System.out.println("This is Hello.");
}
```

Predicate는 함수형 프로그래밍에서 자주 사용되며, 스트림 API에서 filter() 메서드의 파라미터로도 활용됩니다. filter() 메서드는 Predicate를 파라미터로 받아서 해당 조건을 만족하는 요소만을 추출합니다. 다음은 스트림 API를 활용하여 문자열 리스트에서 길이가 6 이상인 요소만을 추출하는 예시입니다.

```java
List<String> stringList = Arrays.asList("apple", "banana", "cherry", "melon", "strawberry");

List<String> filteredList = stringList.stream()
                                      .filter(str -> str.length() >= 6)
                                      .collect(Collectors.toList());
```

<aside>
💡 Predicate를 활용하면, 동적 파라미터화를 구현하는 것이 가능해지며, 코드의 재사용성과 가독성을 높일 수 있습니다.

</aside>

<br>
<br>

# 디폴트 메서드

자바 디폴트 메서드(Default Method)는 인터페이스 내부에서 메서드를 구현할 수 있도록 하는 기능입니다. 이전 버전의 자바에서는 인터페이스에서 메서드를 정의할 수는 있지만, 구현할 수는 없었습니다. 하지만 자바 8에서는 디폴트 메서드를 지원함으로써 인터페이스 내부에서도 메서드를 구현할 수 있게 되었습니다.

디폴트 메서드는 인터페이스 내부에 구현되며, 구현된 메서드는 인터페이스를 구현한 클래스에서 상속받아 사용할 수 있습니다. 이를 통해 기존에 인터페이스를 구현한 클래스에 영향을 주지 않고도, 새로운 메서드를 추가할 수 있습니다.

디폴트 메서드는 다음과 같이 정의됩니다.

```java
public interface MyInterface {
    // 추상 메서드
    void myAbstractMethod();

    // 디폴트 메서드
    default void myDefaultMethod() {
        System.out.println("This is my default method.");
    }
}
```

MyInterface 인터페이스 내부에는 추상 메서드와 디폴트 메서드가 모두 정의되어 있습니다. 추상 메서드는 반드시 구현되어야 하는 메서드이며, 디폴트 메서드는 기본적인 구현이 제공되는 메서드입니다.

인터페이스를 구현한 클래스에서는 디폴트 메서드를 오버라이딩하여 새로운 구현을 제공할 수 있습니다. 디폴트 메서드를 오버라이딩하는 경우, 반드시 super 키워드를 사용하여 인터페이스 내부의 구현을 호출해야 합니다.

디폴트 메서드를 활용하면, 기존에 구현된 인터페이스에 새로운 기능을 추가할 수 있어서 유연한 확장이 가능해집니다. 예를 들어, 컬렉션 프레임워크에서는 Collection 인터페이스에 디폴트 메서드를 추가하여 forEach()와 spliterator() 메서드를 제공합니다. 이를 통해 모든 컬렉션 타입에서 루프를 돌며 요소를 처리할 수 있습니다.


<br>
<br>

# 자바 모듈

자바 모듈(Java Module)은 자바 9부터 추가된 기능으로, 기존의 패키지 시스템을 대체하는 새로운 모듈 시스템입니다. 모듈 시스템은 애플리케이션의 모듈화, 즉 모듈 간의 의존성 관리를 효과적으로 할 수 있도록 도와줍니다.

자바 모듈 시스템은 다음과 같은 장점을 제공합니다.

- 모듈 간의 의존성을 명확하게 정의하여, 라이브러리나 애플리케이션의 종속성 관리를 용이하게 합니다.
- 불필요한 클래스 로딩을 방지하여, 메모리 사용량을 최적화합니다.
- 모듈 내부의 클래스와 패키지를 외부에서 참조하지 못하도록 제한함으로써, 코드의 안정성과 보안성을 높입니다.

모듈 시스템을 사용하려면, 모듈을 정의하고 선언해야 합니다. 모듈은 모듈 디스크립터 파일(module-info.java)에 정의됩니다. 이 파일은 모듈 이름, 의존하는 모듈, 내보내는 패키지 등의 정보를 담고 있습니다.

```java
module com.example.mymodule {
    requires java.base; // 모듈의 의존성 선언
    exports com.example.mymodule.mypackage; // 모듈에서 외부로 내보내는 패키지 선언
}
```

모듈을 사용하기 위해서는, 모듈 경로(Module Path)와 클래스 경로(Class Path)를 구분하여 지정해야 합니다. 모듈 경로는 모듈을 포함한 디렉토리 또는 JAR 파일의 경로를 지정하며, 클래스 경로는 모듈을 포함하지 않는 디렉토리 또는 JAR 파일의 경로를 지정합니다.

모듈 시스템은 자바 9부터 추가된 기능으로 아직은 사용이 제한적이지만, 앞으로 자바 애플리케이션의 모듈화와 의존성 관리를 위한 중요한 기술로 자리 잡을 것으로 예상됩니다.

<br>
<br>

# 자바 스트림

자바 스트림(Stream)은 자바 8부터 추가된 기능으로, 데이터 처리 연산을 지원하는 라이브러리입니다. 스트림은 컬렉션, 배열 등의 데이터 소스를 추상화하여 다양한 연산을 지원하며, 코드의 간결성과 성능 향상을 도와줍니다.

스트림은 크게 중간 연산과 최종 연산으로 구분됩니다. 중간 연산은 데이터를 변환, 필터링하는 등의 작업을 수행하고, 최종 연산은 최종적으로 결과를 도출하는 작업을 수행합니다.

스트림의 사용 예시는 다음과 같습니다.

```java
List<String> strings = Arrays.asList("apple", "banana", "carrot", "date");

// 문자열 길이가 5 이상인 요소만 추출하여 리스트로 반환
List<String> result = strings.stream()
                            .filter(s -> s.length() >= 5)
                            .collect(Collectors.toList());

// 문자열을 대문자로 변환하여 콘솔에 출력
strings.stream()
       .map(String::toUpperCase)
       .forEach(System.out::println);
```

위 예시에서는 스트림을 이용하여 문자열 길이가 5 이상인 요소를 추출하거나, 문자열을 대문자로 변환하여 출력하는 등의 작업을 수행합니다. 이와 같은 스트림의 활용으로 코드의 가독성과 유지 보수성을 높일 수 있습니다.

스트림은 기본형 타입(int, double 등)에 대해서도 별도로 제공되는 IntStream, DoubleStream 등의 클래스를 이용하여 처리할 수 있습니다. 이를 이용하여 박싱과 언박싱 과정을 거치지 않아 성능을 높일 수 있습니다.

<br>
<br>

# 동작 파라미터화 코드 전달하기

동적 파라미터화란, 메서드나 함수의 동작을 실행 시점에 결정하는 기술입니다.

즉, 어떤 동작을 수행할 때 필요한 값을 메서드 외부에서 전달받아 해당 값을 기반으로 동작을 수행하는 것입니다.

자바 8에서는 함수형 프로그래밍을 지원하기 위해 람다 표현식을 도입하였습니다. 람다 표현식은 함수를 값으로 다루기 때문에, 메서드나 함수의 파라미터로 전달할 수 있습니다. 이를 통해 메서드나 함수를 호출할 때마다 다른 동작을 수행하도록 할 수 있습니다.

동적 파라미터화의 대표적인 예시로는 스트림 API에서 제공하는 filter(), map(), reduce() 등이 있습니다. 예를 들어, filter() 메서드는 Predicate<T> 타입의 람다 표현식을 파라미터로 받아 해당 조건을 만족하는 요소만을 추출합니다. 이를 통해 호출할 때마다 다른 조건에 따라 다른 요소만 추출할 수 있습니다.

동적 파라미터화는 코드의 재사용성을 높이고, 가독성을 높이며, 유지보수성을 높일 수 있습니다. 또한, 객체지향 프로그래밍에서 인터페이스를 활용하여 다형성을 구현할 수 있듯이, 함수형 프로그래밍에서는 람다 표현식을 활용하여 동적 파라미터화를 구현할 수 있습니다.
