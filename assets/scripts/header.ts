const burgerBtn = document.querySelector('.burger');
const menu = document.querySelector('.menu-xs');
const appContentContainer = document.querySelector('.app-content');

burgerBtn.addEventListener('click', (event: MouseEvent) => {
    menu.classList.toggle('hidden');
})

appContentContainer.addEventListener('click', (event: MouseEvent) => {
    if(!menu.classList.contains('hidden')) {
        menu.classList.add('hidden');
    }
})