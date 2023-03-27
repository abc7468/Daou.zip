# 매개변수 기본값을 생성하라

- 자바스크립트에서는 매개변수를 선택적으로 적용할 수 있기 때문에 함수에 모든 매개변수를 전달할 필요가 없다. (만일 매개변수를 누락하면 값은 undefined가 된다.)
- 매개변수 기본값은 매개변수에 값을 전달하지 않았을 때 미리 정해둔 값을 기본값으로 사용하는 것을 의미한다.
- 함수를 작성하다 보면 항상 함수에 매개변수를 추가할 일이 생기게 되는데 이 기본값을 사용한다면 변수 검증을 위한 코드를 최소화 할 수 있다.
- 매개변수에 순서가 매겨지기 때문에 매개변수 기본값이 완벽한 해결책은 아니다.
- 기본값이 무엇이든 상관없을 때, 매개변수 기본값을 사용하면 좋다.

# 해체 할당으로 객체 속성에 접근하라

- JS는 해체 할당이라는 과정을 통해 객체에 있는 정보를 곧바로 변수에 할당할 수 있다.
- 객체에 있는 키와 같은 이름의 변수를 생성하고, 객체에 있는 키에 연결된 값을 생성한 변수의 값으로 할당한다.

```jsx
function landscape = {
	photographer: 'Nathan',
};
const { photographer } = landscape;
```

- 값을 할당하는 변수의 이름은 객체에 있는 키와 반드시 일치 해야 한다.
- 중괄호는 변수에 할당되는 값이 객체에 있다는 것을 나타낸다.
- 세개의 마침표와 변수 이름을 작성하면, 이 새로운 변수에 어떠한 추가 정보라도 담을 수 있다.
- 여기서는 펼침 연산자라 부르지 않고 나무지 매개변수라 부른다.

```jsx
function landscape = {
	photographer: 'Nathan',
	equipment: 'canon',
	format: 'digital',
};
const { 
	photographer,
	...additional
} = landscape;

additional;
// { equipment: 'canon',	format: 'digital' }
```

- 키 값과 다른 이름의 변수에 값을 담고 싶다면 콜론에 키 이름을 먼저 쓰고 그 값을 할당할 변수 이름을 입렵하면 된다.

```jsx
function landscape = {
	photographer: 'Nathan',
};
const { photographer: author } = landscape;

author;
//'Nathan'
```

- 배열도 해체 할당이 가능하지만 순서를 맞춰야 한다는 한계가 있다.

```jsx
const landscapi = {
	location: [32.712222, -103.1405556],
};
const { location } = landscape;
const [latitude, longitude] = location;
```

# 키-값 할당을 단순화하라

- 위의 특징을 사용해 객체에서 하나의 값을 제거할 수 있다.

```jsx
const region = {
	city: 'Hobbs',
	county: 'Lea',
	state: {
		name: 'New Mexico',
		abbreviation: 'NM',
	},
};

function setRegion({ location, ...details }){
	const { city, state } = determineCityAndState(location);
	return{
		city,
		state: state.abbreviation,
		...details,
	};
}

```

# 나머지 매개변수로 여러개의 인수를 변수로 전달하라

- 기존에 객체 Array로 return되는 arguments를 마침표 세개를 통해 배열로 return할 수 있다.

```jsx
function getArguments(...args){
	return args;
}
getArguments('A','B')
```

- 그 외에도 나머지 인수를 사용하는 이유를 살펴보자
    1. 인수를 배열로 다루는 것을 다른 개발자들에게 알려야 하는경우
    2. 디버깅에 좋기 때문
    3. 함수 간에 속성을 전달하면서 해당 속성을 조작할 필요가 없을 때