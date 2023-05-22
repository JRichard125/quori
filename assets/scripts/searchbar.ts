import { createApp } from "vue";

createApp({
    compilerOptions: {
        delimiters: ["${", "}$"]
    },
    data() {
        return {
            timeout: null,
            isLoading: false,
            questions: null
        }
    },
    methods : {
        updateInput(event : KeyboardEvent) {
            clearTimeout(this.timeout)
            this.timeout = setTimeout(async () => {
                const value = this.$refs.input.value;
                    if(value?.length) {
                        this.isLoading = true
                    try {
                        const response = await fetch(`/question/search/${this.$refs.input.value}`);
                        const body = await response.json();
                        this.questions = JSON.parse(body);
                    } catch (error) {
                        console.log(error);
                    } finally {
                        this.isLoading = false;
                    }
                } else {
                    this.questions = null;
                }
            }, 1000)
        }
    }
}).mount('#search')