<?php

namespace App\Controller;

use App\Entity\Question;
use App\Form\QuestionType;
use DateTimeZone;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class QuestionController extends AbstractController
{
    #[Route('/question/ask', name: 'ask_question')]
    public function ask(Request $request, EntityManagerInterface $em): Response
    {
        $question = new Question();

        $formQuestion = $this->createForm(QuestionType::class, $question);
        $formQuestion->handleRequest($request);

        if($formQuestion->isSubmitted() && $formQuestion->isValid()) {
            $question->setNbResponse(0);
            $question->setRating(0);
            $question->setCreatedAt(new \DateTimeImmutable(timezone: new DateTimeZone("Europe/Paris")));

            $em->persist($question);
            $em->flush();

            $this->addFlash('succes', 'Votre question a ete ajoutée');

            return $this->redirectToRoute('home');
        }


        return $this->render('question/index.html.twig', ['form' => $formQuestion->createView()]);
    }

    #[Route('/question/{id}', name: 'show_question')]
    public function show(Request $request, string $id) {

        $question = [
            'title'=> 'je suis une question',
            'content'=> 'Lorem, ipsum dolor sit amet consectetur adipisicing elit. Officiis, quis odit! Odit earum quisquam ea animi in qui sit quia. Consequatur illum voluptas quidem, sed et                        numquam neque aspernatur quibusdam.',
            'rating'=> 0,
            'author' => [
                'name'=> 'Laure Joe',
                'avatar' => 'https://randomuser.me/api/portraits/women/79.jpg'
            ],
            'nbResponse'=> 5
        ];

        return $this->render('question/show.html.twig', ['question' => $question]);
    }
}
